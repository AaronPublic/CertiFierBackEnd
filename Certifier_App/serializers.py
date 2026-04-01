import hashlib
import json
from urllib.parse import urlparse
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model

from .models import Template, Certificate, BulkUpload
from .utils.eddsa import sign_data, VERIFY_KEY
from .utils.pdf_renderer import generate_and_attach_certificate_pdf

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
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'role', 'password']
        extra_kwargs = {'password': {'write_only': True, 'required': False}}

    def update(self, instance, validated_data):
        # Kunin ang password at tanggalin sa validated_data
        password = validated_data.pop('password', None)
        
        # I-update ang ibang fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        # Eto ang pinaka-importante:
        if password:
            instance.set_password(password) # Hina-hash nito ang password
            
        instance.save()
        return instance


# ================= TEMPLATE =================
class TemplateSerializer(serializers.ModelSerializer):
    placeholders = serializers.JSONField(required=False)
    background = serializers.ImageField(required=False, allow_null=True)
    signature_image = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = Template
        fields = '__all__'
        read_only_fields = ['id', 'created_by', 'created_at']

    def _secure_url(self, url):
        if not url:
            return None
        parsed = urlparse(url)
        if parsed.scheme == 'http':
            return url.replace('http://', 'https://', 1)
        return url

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['background'] = self._secure_url(data.get('background'))
        data['signature_image'] = self._secure_url(data.get('signature_image'))
        return data


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

        # Render using template background + placeholders when available.
        generate_and_attach_certificate_pdf(cert)

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
        fields = ['id', 'csv_file', 'template']

    def create(self, validated_data):
        request = self.context.get('request')
        user = request.user

        validated_data.pop('uploaded_by', None)

        return BulkUpload.objects.create(
            uploaded_by=user,
            **validated_data
        )