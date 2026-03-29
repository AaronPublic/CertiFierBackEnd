import hashlib
from io import BytesIO
from reportlab.pdfgen import canvas
from django.core.files.base import ContentFile
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model

from .models import Template, Certificate, BulkUpload
from .utils.eddsa import sign_data, VERIFY_KEY

User = get_user_model()

# ================= CUSTOM JWT TOKEN SERIALIZER =================
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom serializer that includes user role and full_name in token response
    """
    def validate(self, attrs):
        data = super().validate(attrs)
        data['user_id'] = self.user.id
        data['email'] = self.user.email
        data['username'] = self.user.username
        data['role'] = self.user.role
        data['full_name'] = f"{self.user.first_name} {self.user.last_name}".strip() or self.user.username
        return data


# ================= USER =================
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'role']


# ================= TEMPLATE =================
class TemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Template
        fields = '__all__'
        read_only_fields = ['id', 'created_by', 'created_at']


# ================= CERTIFICATE =================
class CertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = '__all__'


class CertificateCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = [
            'template',
            'title',
            'full_name',
            'course',
            'issued_by',
            'date_issued',
            'owner'
        ]

    def create(self, validated_data):
        request = self.context.get('request')
        user = request.user

        # Remove duplicate fields just in case
        validated_data.pop('created_by', None)

        # ✅ CREATE CERTIFICATE
        cert = Certificate.objects.create(
            created_by=user,
            **validated_data
        )

        # ✅ CONSISTENT DATA STRING
        data_string = cert.get_data_string()

        # ✅ HASH (TAMPER CHECK)
        data_hash = hashlib.sha256(data_string.encode()).hexdigest()
        cert.data_hash = data_hash
        cert.original_data_hash = data_hash

        # ✅ SIGNATURE (EdDSA)
        cert.signature = sign_data(data_string)

        # ✅ STORE PUBLIC KEY
        cert.public_key = VERIFY_KEY.encode().hex()

        # Save before PDF
        cert.save()

        # ================= PDF GENERATION =================
        buffer = BytesIO()
        p = canvas.Canvas(buffer)

        p.drawString(100, 750, f"Certificate ID: {cert.certificate_id}")
        p.drawString(100, 720, f"Name: {cert.full_name}")
        p.drawString(100, 690, f"Course: {cert.course}")
        p.drawString(100, 660, f"Issued By: {cert.issued_by}")
        p.drawString(100, 630, f"Date: {cert.date_issued}")

        # Optional: show signature snippet
        p.drawString(100, 600, f"Signature: {cert.signature[:30]}...")

        p.showPage()
        p.save()

        buffer.seek(0)

        cert.file.save(
            f"{cert.certificate_id}.pdf",
            ContentFile(buffer.read()),
            save=True
        )

        return cert


# ================= CERTIFICATE PREVIEW =================
class CertificatePreviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = [
            'certificate_id',
            'title',
            'full_name',
            'course',
            'issued_by',
            'date_issued'
        ]


# ================= CERTIFICATE VERIFY =================
class CertificateVerifySerializer(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = [
            'certificate_id',
            'full_name',
            'course',
            'issued_by',
            'date_issued',
            'status'
        ]


# ================= BULK UPLOAD =================
class BulkUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulkUpload
        fields = '__all__'
        read_only_fields = [
            'id',
            'status',
            'total_records',
            'processed_records',
            'created_at'
        ]


class BulkUploadCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulkUpload
        fields = ['csv_file', 'template']

    def create(self, validated_data):
        request = self.context.get('request')
        user = request.user

        validated_data.pop('uploaded_by', None)

        return BulkUpload.objects.create(
            uploaded_by=user,
            **validated_data
        )