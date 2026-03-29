import csv
import hashlib
from io import BytesIO
from django.http import FileResponse
from django.core.files.base import ContentFile
from django.shortcuts import get_object_or_404
from reportlab.pdfgen import canvas
from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, BasePermission
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.views import TokenObtainPairView
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
from django.contrib.auth import get_user_model
from .serializers import UserSerializer, CustomTokenObtainPairSerializer

User = get_user_model()


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
    serializer_class = CertificateSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        if self.request.user.role != 'admin':
            raise PermissionDenied("Only admins can edit certificates")
        serializer.save()

    def perform_destroy(self, instance):
        if self.request.user.role != 'admin':
            raise PermissionDenied("Only admins can delete certificates")
        instance.delete()


# ================= VERIFY (PUBLIC) =================
@api_view(['GET'])
@permission_classes([AllowAny])
def verify_certificate(request, certificate_id):
    cert = get_object_or_404(Certificate, certificate_id=certificate_id)

    data_string = cert.get_data_string()

    current_hash = hashlib.sha256(data_string.encode()).hexdigest()

    if cert.original_data_hash and current_hash != cert.original_data_hash:
        cert.status = "INVALID"
        cert.save(update_fields=['status'])

        return Response({
            "certificate_id": cert.certificate_id,
            "status": "INVALID - DATA TAMPERED"
        })

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
        })

    cert.status = "VALID"
    cert.save(update_fields=['status'])

    return Response({
        "certificate_id": cert.certificate_id,
        "full_name": cert.full_name,
        "course": cert.course,
        "issued_by": cert.issued_by,
        "date_issued": cert.date_issued,
        "status": cert.status
    })


# ================= DOWNLOAD PDF =================
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_certificate(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)
    if cert.owner != request.user and request.user.role != 'admin':
        return Response({"error": "Unauthorized"}, status=403)

    buffer = BytesIO()
    p = canvas.Canvas(buffer)

    p.drawString(100, 750, f"Certificate ID: {cert.certificate_id}")
    p.drawString(100, 720, f"Name: {cert.full_name}")
    p.drawString(100, 690, f"Course: {cert.course}")
    p.drawString(100, 660, f"Issued By: {cert.issued_by}")
    p.drawString(100, 630, f"Date: {cert.date_issued}")

    p.showPage()
    p.save()

    buffer.seek(0)

    return FileResponse(
        buffer,
        as_attachment=True,
        filename=f"{cert.certificate_id}.pdf"

    )


# ================= CERTIFICATE PREVIEW =================
class CertificatePreviewView(generics.RetrieveAPIView):
    queryset = Certificate.objects.all()
    serializer_class = CertificatePreviewSerializer
    permission_classes = [IsAuthenticated]


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

            # Generate PDF
            buffer = BytesIO()
            p = canvas.Canvas(buffer)
            p.drawString(100, 750, f"Certificate ID: {cert.certificate_id}")
            p.drawString(100, 720, f"Name: {cert.full_name}")
            p.drawString(100, 690, f"Course: {cert.course}")
            p.drawString(100, 660, f"Issued By: {cert.issued_by}")
            p.drawString(100, 630, f"Date: {cert.date_issued}")
            p.showPage()
            p.save()
            buffer.seek(0)

            cert.file.save(
                f"{cert.certificate_id}.pdf",
                ContentFile(buffer.read()),
                save=True
            )

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