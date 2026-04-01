import csv
import hashlib
import uuid
from io import BytesIO
from urllib.parse import urlparse
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, BasePermission
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Template, Certificate, BulkUpload
from .serializers import (
    CertificateSerializer,
    CertificateCreateSerializer,
    TemplateSerializer,
    BulkUploadSerializer,
    BulkUploadCreateSerializer,
    CertificatePreviewSerializer
)

from .utils.eddsa import sign_data, VERIFY_KEY, verify_signature
from .utils.pdf_renderer import generate_and_attach_certificate_pdf, build_certificate_pdf_bytes
from .utils.google_oauth import (
    get_google_auth_url,
    exchange_code_for_token,
    get_user_info_from_id_token,
    get_user_info_from_access_token,
    validate_school_email,
)
from django.contrib.auth import get_user_model
from .serializers import UserSerializer, CustomTokenObtainPairSerializer
from django.views.decorators.clickjacking import xframe_options_exempt
import secrets
from rest_framework.parsers import MultiPartParser, FormParser

User = get_user_model()


# ================= UTILITY HELPERS =================
def _secure_url(url):
    """Normalize URL to HTTPS for production/iframe safety."""
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme == 'http':
        return url.replace('http://', 'https://', 1)
    return url


# ================= GOOGLE OAUTH HELPERS =================
def get_or_create_user_from_google(google_user_data):
    """
    Get or create user from Google OAuth data
    
    Args:
        google_user_data: Dictionary with email, name, picture from Google
    
    Returns:
        Tuple (user, created) where created is bool indicating if user was created
    """
    email = google_user_data.get('email')
    
    if not email:
        raise ValueError("Google response missing email field")
    
    # Validate school email
    if not validate_school_email(email):
        raise PermissionDenied(f"Only @ua.edu.ph emails are allowed. You provided: {email}")
    
    # Extract name from Google data
    name = google_user_data.get('name', email.split('@')[0])
    name_parts = name.split(' ', 1)
    first_name = name_parts[0] if name_parts else 'User'
    last_name = name_parts[1] if len(name_parts) > 1 else ''
    
    # Get or create user
    user, created = User.objects.get_or_create(
        email=email,
        defaults={
            'username': email.split('@')[0] + '_' + str(uuid.uuid4())[:6],
            'first_name': first_name[:30],
            'last_name': last_name[:30],
            'role': 'student',  # Default role for OAuth users
        }
    )
    
    return user, created


# ================= GOOGLE OAUTH ENDPOINTS =================
@api_view(['GET'])
@permission_classes([AllowAny])
def google_login_initiate(request):
    """
    Initiate Google OAuth login flow
    
    Query params:
        return_to: URL to redirect to after auth (required)
        hd: Hosted domain restriction (default: ua.edu.ph)
    
    Returns:
        Redirect to Google OAuth consent screen
    """
    return_to = request.query_params.get('return_to')
    hd = request.query_params.get('hd', 'ua.edu.ph')
    
    if not return_to:
        return Response(
            {'error': 'return_to parameter is required'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Generate state token for CSRF protection
    state = f"{secrets.token_urlsafe(32)}:{return_to}"
    
    # Store state in session for verification in callback
    request.session['google_oauth_state'] = state
    request.session['google_oauth_return_to'] = return_to
    request.session.save()
    
    try:
        # Get Google auth URL
        google_auth_url = get_google_auth_url(state, return_to, hd)
    except ValueError as exc:
        return Response({'error': str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return HttpResponseRedirect(google_auth_url)


@api_view(['GET'])
@permission_classes([AllowAny])
def google_callback(request):
    """
    Handle Google OAuth callback
    
    Query params:
        code: Authorization code from Google
        state: State token for CSRF verification
        error: Error message if auth failed
    
    Returns:
        Redirect to return_to URL with access token, role, and full_name
    """
    error = request.query_params.get('error')
    state = request.query_params.get('state')
    code = request.query_params.get('code')
    
    # Get stored return_to and state from session
    session_state = request.session.get('google_oauth_state')
    return_to = request.session.get('google_oauth_return_to', '/login')
    
    # Handle user cancellations or Google errors
    if error:
        error_msg = {
            'access_denied': 'You denied access to Google account',
            'invalid_scope': 'Invalid scope requested',
            'invalid_request': 'Invalid request to Google',
        }.get(error, f'Google auth error: {error}')
        
        return_url = f"{return_to}?error={error_msg}"
        return HttpResponseRedirect(return_url)
    
    # Validate state for CSRF protection
    if not session_state or not state or state != session_state:
        return_url = f"{return_to}?error=CSRF validation failed"
        return HttpResponseRedirect(return_url)
    
    if not code:
        return_url = f"{return_to}?error=No authorization code received"
        return HttpResponseRedirect(return_url)
    
    try:
        # Exchange code for token
        token_data = exchange_code_for_token(code)
        id_token_str = token_data.get('id_token')
        access_token_str = token_data.get('access_token')
        
        if not id_token_str:
            return_url = f"{return_to}?error=Failed to retrieve ID token"
            return HttpResponseRedirect(return_url)
        
        # Get user info from ID token
        try:
            user_data = get_user_info_from_id_token(id_token_str)
        except Exception:
            # Fallback to access token if ID token fails
            user_data = get_user_info_from_access_token(access_token_str)
        
        # Get or create user
        user, created = get_or_create_user_from_google(user_data)
        
        # Generate JWT tokens for our app
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        # Get full name
        full_name = f"{user.first_name} {user.last_name}".strip() or user.username
        
        # Clear session data
        request.session.pop('google_oauth_state', None)
        request.session.pop('google_oauth_return_to', None)
        request.session.save()
        
        # Build redirect URL with tokens
        params = {
            'access': access_token,
            'role': user.role,
            'full_name': full_name,
        }
        
        from urllib.parse import urlencode
        redirect_url = f"{return_to}?{urlencode(params)}"
        
        return HttpResponseRedirect(redirect_url)
    
    except PermissionDenied as e:
        # School email validation failed
        return_url = f"{return_to}?error={str(e)}"
        return HttpResponseRedirect(return_url)
    except Exception as e:
        # Generic error handling
        error_msg = f"Authentication failed: {str(e)}"
        return_url = f"{return_to}?error={error_msg}"
        return HttpResponseRedirect(return_url)


# ================= AUTH: CUSTOM TOKEN VIEW =================
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom login endpoint that returns access token + refresh token + user info
    """
    serializer_class = CustomTokenObtainPairSerializer

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
class IsAdminUserRole(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'


# ================= AUTH: REGISTER =================
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    """Register new user"""
    
    email = request.data.get('email')
    username = request.data.get('username') or email
    password = request.data.get('password')
    first_name = (request.data.get('first_name') or '').strip()
    last_name = (request.data.get('last_name') or '').strip()
    role = request.data.get('role', 'student')  # Default to student

    if not email or not password or not first_name or not last_name:
        return Response(
            {"error": "email, password, first_name, and last_name are required"},
            status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(email=email).exists():
        return Response(
            {"error": "Email already exists"},
            status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(username=username).exists():
        return Response(
            {"error": "Username already exists"},
            status=status.HTTP_400_BAD_REQUEST
        )

    if role not in ['student', 'admin']:
        return Response(
            {"error": "Role must be 'student' or 'admin'"},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = User.objects.create_user(
        email=email,
        username=username,
        password=password,
        first_name=first_name,
        last_name=last_name,
        role=role
    )

    return Response({
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "full_name": f"{user.first_name} {user.last_name}".strip(),
        "role": user.role
    }, status=status.HTTP_201_CREATED)



# ================= STUDENT: VIEW OWN CERTS =================
class MyCertificatesView(generics.ListAPIView):
    serializer_class = CertificateSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Certificate.objects.filter(owner=self.request.user)


# ================= CERTIFICATE CRUD =================
class CertificateListView(generics.ListAPIView):
    serializer_class = CertificateSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        if user.role == 'admin':
            return Certificate.objects.all()
        return Certificate.objects.filter(owner=user)


class CertificateCreateView(generics.CreateAPIView):
    queryset = Certificate.objects.all()
    serializer_class = CertificateCreateSerializer
    permission_classes = [IsAdminUserRole]

    def perform_create(self, serializer):
        serializer.save(
            created_by=self.request.user,
            owner=self.request.user
        )


class CertificateDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Certificate.objects.all() # Idagdag ang queryset dito
    serializer_class = CertificateSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        if self.request.user.role != 'admin':
            raise PermissionDenied("Only admins can edit certificates")
        serializer.save()

    def perform_destroy(self, instance):
        # 1. Check kung admin ang nagbubura
        if self.request.user.role != 'admin':
            raise PermissionDenied("Only admins can delete certificates")
        
        # 2. (Optional pero Recommended) Burahin din ang file sa storage
        if instance.file:
            instance.file.delete(save=False)
            
        # 3. Burahin ang record sa database
        instance.delete()


def _get_or_generate_certificate_pdf(cert):
    # If the certificate has a visual template, regenerate to avoid serving
    # previously cached plain fallback PDFs from older deployments.
    if cert.template_id and cert.template and cert.template.background:
        try:
            generate_and_attach_certificate_pdf(cert)
            return cert.file.open('rb')
        except Exception:
            pass

    if cert.file and cert.file.name:
        try:
            if cert.file.storage.exists(cert.file.name):
                return cert.file.open('rb')
        except Exception:
            pass

    # First try persisted storage-backed PDF so future requests can reuse it.
    try:
        generate_and_attach_certificate_pdf(cert)
        return cert.file.open('rb')
    except Exception:
        # Fallback: stream generated bytes without relying on storage backend.
        pdf_bytes = build_certificate_pdf_bytes(cert)
        return BytesIO(pdf_bytes)


# ================= VERIFY (PUBLIC) =================
@api_view(['GET'])
@permission_classes([AllowAny])
@xframe_options_exempt
def verify_certificate(request, certificate_id):
    
    # 1. Kunin ang certificate o mag-return ng 404
    cert = get_object_or_404(Certificate, certificate_id=certificate_id)

    # 2. Integrity Check (Hashing)
    data_string = cert.get_data_string()
    current_hash = hashlib.sha256(data_string.encode()).hexdigest()

    if cert.original_data_hash and current_hash != cert.original_data_hash:
        cert.status = "INVALID"
        cert.save(update_fields=['status'])
        return Response({
            "certificate_id": cert.certificate_id,
            "status": "INVALID - DATA TAMPERED"
        }, status=status.HTTP_200_OK)

    # 3. Signature Verification (EdDSA)
    is_valid = verify_signature(
        data_string,
        cert.signature,
        cert.public_key   
    )

    if not is_valid:
        cert.status = "INVALID"
        cert.save(update_fields=['status'])
        return Response({
            "certificate_id": cert.certificate_id,
            "status": "INVALID - SIGNATURE FAIL"
        }, status=status.HTTP_200_OK)

    # 4. Success Logic
    cert.status = "VALID"
    cert.save(update_fields=['status'])

    # Always return a public preview endpoint URL for verify flows.
    file_url = _secure_url(
        request.build_absolute_uri(
            reverse('verify_certificate_preview', args=[cert.certificate_id])
        )
    )

    return Response({
        "certificate_id": cert.certificate_id,
        "full_name": cert.full_name,
        "course": cert.course,
        "issued_by": cert.issued_by,
        "date_issued": cert.date_issued,
        "status": cert.status,
        "file_url": file_url  # Importante ito para sa preview
    })


@api_view(['GET'])
@permission_classes([AllowAny])
@xframe_options_exempt
def verify_certificate_preview(request, certificate_id):
    try:
        cert = get_object_or_404(Certificate, certificate_id=certificate_id)

        file_obj = _get_or_generate_certificate_pdf(cert)

        return FileResponse(
            file_obj,
            content_type='application/pdf',
            as_attachment=False,
            filename=f"{cert.certificate_id}.pdf"
        )
    except Exception as exc:
        return Response({'error': f'Preview generation failed: {str(exc)}'}, status=500)

# ================= USER MANAGEMENT (ADMIN ONLY) =================

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Endpoint para makuha, ma-edit, o mabura ang isang specific user.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUserRole] # Siguradong admin lang ang pwedeng gumalaw nito

    def perform_destroy(self, instance):
        # Proteksyon: Iwasan na mabura ng admin ang sarili niyang account
        if instance == self.request.user:
            raise PermissionDenied("You cannot delete your own admin account.")
        instance.delete()

# ================= DOWNLOAD PDF =================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_certificate(request, pk):
    try:
        cert = get_object_or_404(Certificate, pk=pk)

        if cert.owner != request.user and request.user.role != 'admin':
            return Response({"error": "Unauthorized"}, status=403)

        file_obj = _get_or_generate_certificate_pdf(cert)

        return FileResponse(
            file_obj,
            content_type='application/pdf',
            as_attachment=True,
            filename=f"{cert.certificate_id}.pdf"
        )
    except Exception as exc:
        return Response({'error': f'Download failed: {str(exc)}'}, status=500)


# ================= CERTIFICATE PREVIEW =================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
@xframe_options_exempt
def preview_certificate(request, pk):
    try:
        cert = get_object_or_404(Certificate, pk=pk)

        if cert.owner != request.user and request.user.role != 'admin':
            return Response({"error": "Unauthorized"}, status=403)

        file_obj = _get_or_generate_certificate_pdf(cert)

        return FileResponse(
            file_obj,
            content_type='application/pdf',
            as_attachment=False,
            filename=f"{cert.certificate_id}.pdf"
        )
    except Exception as exc:
        return Response({'error': f'Preview failed: {str(exc)}'}, status=500)


# ================= TEMPLATE =================
class TemplateView(generics.ListCreateAPIView):
    queryset = Template.objects.all()
    serializer_class = TemplateSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class TemplateDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Template.objects.all()
    serializer_class = TemplateSerializer
    permission_classes = [IsAdminUserRole]


# ================= BULK UPLOAD =================
class BulkUploadListView(generics.ListAPIView):
    serializer_class = BulkUploadSerializer
    permission_classes = [IsAdminUserRole]

    def get_queryset(self):
        return BulkUpload.objects.all()


class BulkUploadCreateView(generics.CreateAPIView):
    queryset = BulkUpload.objects.all()
    serializer_class = BulkUploadCreateSerializer
    permission_classes = [IsAdminUserRole]

    def perform_create(self, serializer):
        serializer.save(uploaded_by=self.request.user)


# ================= GENERATE CERTS FROM CSV =================
@api_view(['POST'])
@permission_classes([IsAdminUserRole])
def process_bulk_upload(request, pk):
    upload = get_object_or_404(BulkUpload, pk=pk)

    try:
        # Read CSV and count total rows
        with upload.csv_file.open() as file:
            decoded = file.read().decode('utf-8').splitlines()
            reader = list(csv.DictReader(decoded))  # Convert to list to count rows

        if not reader:
            upload.status = "FAILED"
            upload.save(update_fields=['status'])
            return Response({"error": "CSV file is empty"}, status=400)

        # Validate required columns exist
        required_cols = {'title', 'full_name', 'course', 'issued_by', 'date_issued'}
        if not reader[0]:
            upload.status = "FAILED"
            upload.save(update_fields=['status'])
            return Response({"error": "CSV has no header row"}, status=400)

        missing_cols = required_cols - set(reader[0].keys())
        if missing_cols:
            upload.status = "FAILED"
            upload.save(update_fields=['status'])
            return Response({
                "error": f"CSV missing required columns: {', '.join(sorted(missing_cols))}"
            }, status=400)

        upload.status = "PROCESSING"
        upload.total_records = len(reader)
        upload.processed_records = 0
        upload.save()

        created = []

        for idx, row in enumerate(reader, start=1):
            try:
                user = request.user  

                cert = Certificate.objects.create(
                    template=upload.template,
                    title=str(row.get('title', '')).strip(),
                    full_name=str(row.get('full_name', '')).strip(),
                    course=str(row.get('course', '')).strip(),
                    issued_by=str(row.get('issued_by', '')).strip(),
                    date_issued=row.get('date_issued'),
                    created_by=user,
                    owner=user
                )

                # EdDSA signing and hash
                data_string = cert.get_data_string()
                cert.data_hash = hashlib.sha256(data_string.encode()).hexdigest()
                cert.original_data_hash = cert.data_hash
                cert.signature = sign_data(data_string)
                cert.public_key = VERIFY_KEY.encode().hex()
                cert.save()

                # PDF generation with error catching
                try:
                    generate_and_attach_certificate_pdf(cert)
                except Exception as pdf_error:
                    print(f"PDF generation failed for row {idx}: {str(pdf_error)}")
                    # Continue processing even if PDF fails; cert is saved

                created.append(cert.certificate_id)

            except Exception as row_error:
                print(f"Row {idx} failed: {str(row_error)}")
                upload.status = "FAILED"
                upload.save(update_fields=['status'])
                return Response({
                    "error": f"Error processing row {idx}: {str(row_error)}"
                }, status=400)

            # Update processed_records dynamically
            upload.processed_records += 1
            upload.save(update_fields=['processed_records'])

        # Mark as completed
        upload.status = "COMPLETED"
        upload.save(update_fields=['status'])

        return Response({"created": created, "total": len(created)})

    except Exception as e:
        print(f"Bulk upload failed: {str(e)}")
        upload.status = "FAILED"
        upload.save(update_fields=['status'])
        return Response({"error": f"Upload processing failed: {str(e)}"}, status=500)