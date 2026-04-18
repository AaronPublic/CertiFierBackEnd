from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # ================= AUTH =================
    path('auth/register/', views.register, name='register'),
    path('auth/login/', views.CustomTokenObtainPairView.as_view(), name='turoken_obtain_pair'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # ================= GOOGLE OAUTH =================
    path('auth/google/login/', views.google_login_initiate, name='google_login_initiate'),
    path('auth/google/callback/', views.google_callback, name='google_callback'),

    # ================= STUDENT =================
    path('my-certificates/', views.MyCertificatesView.as_view()),

    path('verify/<str:certificate_id>/', views.verify_certificate, name='verify_certificate'),

    path('certificates/<uuid:pk>/download/', views.download_certificate),


    # ================= CERTIFICATES =================
    path('certificates/', views.CertificateListView.as_view()),
    path('certificates/create/', views.CertificateCreateView.as_view()),
    path('certificates/<uuid:pk>/', views.CertificateDetailView.as_view()),
    path('certificates/<uuid:pk>/preview/', views.preview_certificate),
    path('certificates/<uuid:pk>/reissue/', views.reissue_certificate),


    # ================= TEMPLATE ================= 
    path('templates/', views.TemplateView.as_view()),
    path('templates/<uuid:pk>/', views.TemplateDetailView.as_view()),


    # ================= BULK UPLOAD =================
    path('uploads/', views.BulkUploadListView.as_view()),
    path('uploads/create/', views.BulkUploadCreateView.as_view()),
    path('uploads/<uuid:pk>/process/', views.process_bulk_upload),
    
    #ALL USERS
    path('users/', views.UserListView.as_view()),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),
]