import hashlib
from io import BytesIO
from reportlab.pdfgen import canvas
from django.core.files.base import ContentFile
from rest_framework import serializers

from .models import User, Template, Certificate, BulkUpload
from .utils.eddsa import sign_data, VERIFY_KEY

#TRY FOR ALL USERS
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'role']

# ================= USER =================
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'role']


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
        # Kunin ang kasalukuyang logged-in user mula sa context
        user = self.context['request'].user

        # ETO ANG FIX: Alisin ang created_by sa validated_data para hindi mag-duplicate
        validated_data.pop('created_by', None)

        # Ngayon, isa na lang ang created_by na mapapasa
        cert = Certificate.objects.create(
            created_by=user,
            **validated_data
        )

        # Generate hash
        data_string = cert.get_data_string()
        cert.data_hash = hashlib.sha256(data_string.encode()).hexdigest()
        cert.original_data_hash = cert.data_hash

        # ⚡ EdDSA signing for manual create
        cert.signature = sign_data(data_string)
        cert.public_key = VERIFY_KEY.encode().hex()

        # I-save ang initial data (hash at signature)
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
        # I-save ang generated PDF file sa model
        cert.file.save(
            f"{cert.certificate_id}.pdf",
            ContentFile(buffer.read()),
            save=True
        )

        return cert


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
            'error_log',
            'created_at'
        ]


class BulkUploadCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = BulkUpload
        fields = ['csv_file', 'template']

    def create(self, validated_data):
        user = self.context['request'].user
        
        # Siguraduhin ding walang duplicate dito kung sakali
        validated_data.pop('uploaded_by', None)

        return BulkUpload.objects.create(
            uploaded_by=user,
            **validated_data
        )