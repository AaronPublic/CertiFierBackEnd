import csv
import hashlib
from io import BytesIO
from django.http import FileResponse
from django.core.files.base import ContentFile
from django.shortcuts import get_object_or_404
from reportlab.pdfgen import canvas
from rest_framework import generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
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
from rest_framework.permissions import IsAuthenticated #Try
from rest_framework.permissions import BasePermission
from django.contrib.auth import get_user_model
from .serializers import UserSerializer

User = get_user_model()

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    
class IsAdminUserRole(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.role == 'admin'


# ================= TEST USER HELPER =================
from django.contrib.auth import get_user_model
User = get_user_model()



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

    current_hash = hashlib.sha256(cert.get_data_string().encode()).hexdigest()

    if cert.original_data_hash and current_hash != cert.original_data_hash:
        cert.status = "INVALID"
        cert.save()
        return Response({
            "certificate_id": certificate_id,
            "status": "INVALID - DATA TAMPERED"
        })

    if not verify_signature(cert.get_data_string(), cert.signature):
        cert.status = "INVALID"
        cert.save()
        return Response({
            "certificate_id": certificate_id,
            "status": "INVALID - SIGNATURE FAIL"
        })

    cert.status = "VALID"
    cert.save()

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