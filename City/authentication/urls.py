from django.urls import path
from .views import *

urlpatterns = [
    path('business/register/', RegisterView.as_view(), name='register'),
    path('business/verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('business/login/', LoginView.as_view(), name='login'),
    path('business/cleanup/', CleanupTemporaryRegistrationsView.as_view(), name='cleanup'),
    path('business/forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('business/reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('business/logout/', LogoutView.as_view(), name='logout'),
    path('business/locations/',PublicLocationListView.as_view(), name='public-locations'), 

    path('admin/login/', AdminLoginView.as_view(), name='admin-login'),
    path('admin/locations/',AdminLocationView.as_view(), name='admin-locations'),
    path('admin/locations/<int:pk>/', AdminLocationDetailView.as_view(), name='admin-location-detail'), 



]