from django.contrib import admin
from .models import User, Certificate, Template, BulkUpload
admin.site.register(User)
admin.site.register(Certificate)
admin.site.register(Template)
admin.site.register(BulkUpload)

# Register your models here.
