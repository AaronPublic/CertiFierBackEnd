import csv
import hashlib
import uuid
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
from .utils.pdf_renderer import generate_and_attach_certificate_pdf
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

User = get_user_model()


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
    
    # Get Google auth URL
    google_auth_url = get_google_auth_url(state, return_to, hd)
    
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


# ================= REISSUE CERTIFICATE =================
@api_view(['POST'])
@permission_classes([IsAdminUserRole])
def reissue_certificate(request, pk):
    """Reissue a certificate with updated information"""
    cert = get_object_or_404(Certificate, pk=pk)
    
    try:
        # Create new certificate with updated data
        new_cert = Certificate.objects.create(
            template=cert.template,
            title=request.data.get('title', cert.title),
            full_name=request.data.get('full_name', cert.full_name),
            course=request.data.get('course', cert.course),
            issued_by=request.data.get('issued_by', cert.issued_by),
            date_issued=request.data.get('date_issued', cert.date_issued),
            created_by=request.user,
            owner_id=request.data.get('owner') or cert.owner_id
        )
        
        # EdDSA signing and hash
        data_string = new_cert.get_data_string()
        new_cert.data_hash = hashlib.sha256(data_string.encode()).hexdigest()
        new_cert.original_data_hash = new_cert.data_hash
        new_cert.signature = sign_data(data_string)
        new_cert.public_key = VERIFY_KEY.encode().hex()
        new_cert.save()
        
        # Generate PDF
        generate_and_attach_certificate_pdf(new_cert)
        
        return Response(
            CertificateSerializer(new_cert).data,
            status=status.HTTP_201_CREATED
        )
    except Exception as e:
        return Response(
            {"error": str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )


def _get_or_generate_certificate_pdf(cert):
    if cert.file and cert.file.name:
        try:
            if cert.file.storage.exists(cert.file.name):
                return cert.file.open('rb')
        except Exception:
            pass

    generate_and_attach_certificate_pdf(cert)
    return cert.file.open('rb')


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

    # Kunin ang absolute URL ng file para ma-access ng React
    file_url = None
    if cert.file:
        file_url = request.build_absolute_uri(cert.file.url)

    return Response({
        "certificate_id": cert.certificate_id,
        "full_name": cert.full_name,
        "course": cert.course,
        "issued_by": cert.issued_by,
        "date_issued": cert.date_issued,
        "status": cert.status,
        "file_url": file_url  # Importante ito para sa preview
    })

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
    cert = get_object_or_404(Certificate, pk=pk)

    if cert.owner != request.user and request.user.role != 'admin':
        return Response({"error": "Unauthorized"}, status=403)

    file_obj = _get_or_generate_certificate_pdf(cert)

    return FileResponse(
        file_obj,
        as_attachment=True,
        filename=f"{cert.certificate_id}.pdf"
    )


# ================= CERTIFICATE PREVIEW =================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def preview_certificate(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)

    if cert.owner != request.user and request.user.role != 'admin':
        return Response({"error": "Unauthorized"}, status=403)

    file_obj = _get_or_generate_certificate_pdf(cert)

    return FileResponse(
        file_obj,
        as_attachment=False,
        filename=f"{cert.certificate_id}.pdf"
    )


# ================= TEMPLATE =================
class TemplateView(generics.ListCreateAPIView):
    queryset = Template.objects.all()
    serializer_class = TemplateSerializer
    permission_classes = [IsAdminUserRole]

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

        upload.status = "PROCESSING"
        upload.total_records = len(reader)
        upload.processed_records = 0
        upload.save()

        created = []

        for row in reader:
            user = request.user  

            cert = Certificate.objects.create(
                template=upload.template,
                title=row['title'],
                full_name=row['full_name'],
                course=row['course'],
                issued_by=row['issued_by'],
                date_issued=row['date_issued'],
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

            generate_and_attach_certificate_pdf(cert)

            created.append(cert.certificate_id)

            # Update processed_records dynamically
            upload.processed_records += 1
            upload.save(update_fields=['processed_records'])

        # Mark as completed
        upload.status = "COMPLETED"
        upload.save(update_fields=['status'])

        return Response({"created": created})

    except Exception as e:
        # Mark upload as failed in case of error
        upload.status = "FAILED"
        upload.save(update_fields=['status'])
        return Response({"error": str(e)}, status=500)