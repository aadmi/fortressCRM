from django.urls import path
from .views import RegisterView, VerifyAccountView, LoginView, ProtectedView, InitialLoginView, SuccessView

urlpatterns = [
    path('register', RegisterView.as_view(), name='register'),
    path('verify_account/', VerifyAccountView.as_view(), name='verify_account'),
    path('login/', LoginView.as_view(), name='login'),
    path('login-otp/', InitialLoginView.as_view(), name='login-otp'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path('success/', SuccessView.as_view(), name='success'),
    path('home/', SuccessView.as_view(), name='home'),
    #path('email_verification/', VerifyAccountView.as_view(), name='email_verification'),
# Add new URLs for OTP generation and OTP entry/login
#     path('generate-otp/', YourGenerateOTPView.as_view(), name='generate-otp'),
#     path('enter-otp/', YourEnterOTPView.as_view(), name='enter-otp'),
]
