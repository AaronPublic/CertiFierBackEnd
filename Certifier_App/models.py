from django.db import models
from django.conf import settings
import uuid
from django.contrib.auth.models import AbstractUser


# ================= USER ========================================================
class User(AbstractUser):
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=20, choices=[
        ('student', 'Student'),
        ('admin', 'Administrator')
    ])

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def __str__(self):
        return self.username


# ================= TEMPLATE =====================================================
class Template(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=255)

    background = models.FileField(upload_to='templates/')

    signature_image = models.ImageField(
        upload_to='templates/signatures/',
        null=True,
        blank=True
    )

    placeholders = models.JSONField()

    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


# ================= CERTIFICATE =================================================
def generate_certificate_id():
    return f"CERT-{uuid.uuid4().hex[:8].upper()}"

class Certificate(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    certificate_id = models.CharField(
        max_length=100,
        unique=True,
        default=generate_certificate_id,
    )

    template = models.ForeignKey(
        Template,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='certificates'
    )

    title = models.CharField(max_length=255)
    full_name = models.CharField(max_length=255)
    course = models.CharField(max_length=255)
    issued_by = models.CharField(max_length=255)
    date_issued = models.DateField()

    # 🔐 EdDSA
    signature = models.TextField()
    public_key = models.TextField()
    data_hash = models.TextField()
    original_data_hash = models.TextField(null=True, blank=True) # ADD original_data_hash

    STATUS_CHOICES = (
        ('VALID', 'Valid'),
        ('INVALID', 'Invalid'),
        ('REVOKED', 'Revoked'),
    )
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='VALID')

    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='certificates'
    )

    file = models.FileField(upload_to='certificates/', null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def get_data_string(self):
        return f"{self.title}|{self.full_name}|{self.course}|{self.issued_by}|{self.date_issued}|{self.certificate_id}"
    
    


# ================= BULK UPLOAD =================================================
class BulkUpload(models.Model):

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    csv_file = models.FileField(upload_to='csv_uploads/')

    # Link to template (IMPORTANT)
    template = models.ForeignKey(Template, on_delete=models.CASCADE)

    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')

    total_records = models.IntegerField(default=0)
    processed_records = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Upload {self.id} - {self.status}"