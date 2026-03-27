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

#TRYYY
from django.contrib.auth import get_user_model
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics
from .serializers import UserSerializer

User = get_user_model()

class UserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]  # pwede mo palitan later


# ================= TEST USER HELPER =================
from django.contrib.auth import get_user_model
User = get_user_model()

def get_test_user():
    return User.objects.first()


# ================= STUDENT: VIEW OWN CERTS =================
class MyCertificatesView(generics.ListAPIView):
    serializer_class = CertificateSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return Certificate.objects.all()


# ================= CERTIFICATE CRUD =================
class CertificateListView(generics.ListAPIView):
    queryset = Certificate.objects.all()
    serializer_class = CertificateSerializer
    permission_classes = [AllowAny]


class CertificateCreateView(generics.CreateAPIView):
    queryset = Certificate.objects.all()
    serializer_class = CertificateCreateSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        user = get_test_user()
        serializer.save(created_by=user, owner=user)


class CertificateDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Certificate.objects.all()
    serializer_class = CertificateSerializer
    permission_classes = [AllowAny]


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
@permission_classes([AllowAny])
def download_certificate(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)

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
    permission_classes = [AllowAny]


# ================= TEMPLATE =================
class TemplateView(generics.ListCreateAPIView):
    queryset = Template.objects.all()
    serializer_class = TemplateSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        serializer.save(created_by=get_test_user())


class TemplateDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Template.objects.all()
    serializer_class = TemplateSerializer
    permission_classes = [AllowAny]


# ================= BULK UPLOAD =================
class BulkUploadListView(generics.ListAPIView):
    serializer_class = BulkUploadSerializer
    permission_classes = [AllowAny]

    def get_queryset(self):
        return BulkUpload.objects.all()


class BulkUploadCreateView(generics.CreateAPIView):
    queryset = BulkUpload.objects.all()
    serializer_class = BulkUploadCreateSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        serializer.save(uploaded_by=get_test_user())


# ================= GENERATE CERTS FROM CSV =================
@api_view(['POST'])
@permission_classes([AllowAny])
def process_bulk_upload(request, pk):
    upload = get_object_or_404(BulkUpload, pk=pk)

    created = []

    with upload.csv_file.open() as file:
        decoded = file.read().decode('utf-8').splitlines()
        reader = csv.DictReader(decoded)

        for row in reader:
            user = get_test_user()

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

            data_string = cert.get_data_string()
            cert.data_hash = hashlib.sha256(data_string.encode()).hexdigest()
            cert.original_data_hash = cert.data_hash

            cert.signature = sign_data(data_string)
            cert.public_key = VERIFY_KEY.encode().hex()

            cert.save()

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

    upload.status = "COMPLETED"
    upload.total_records = len(created)
    upload.processed_records = len(created)
    upload.save()

    return Response({"created": created})