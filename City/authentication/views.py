from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import PermissionDenied
from .models import PasswordResetOTP
from .serializers import ForgotPasswordSerializer, ResetPasswordSerializer
import random
from rest_framework.permissions import IsAuthenticated
from .models import TemporaryRegistration, CustomShopUser, Shop
from .serializers import RegisterSerializer, VerifyOTPSerializer, LoginSerializer
from datetime import timedelta

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            phone_number = serializer.validated_data['phone_number'] # Phone number edukunnnu
            
            # 1. Check if Email already exists in User table
            if CustomShopUser.objects.filter(email=email).exists():
                return Response({"error": "Email is already registered."}, status=status.HTTP_400_BAD_REQUEST)
            
            # 2. Check if Phone Number already exists in Shop table (NEW LOGIC)
            if Shop.objects.filter(phone_number=phone_number).exists():
                return Response({"error": "Phone number is already registered."}, status=status.HTTP_400_BAD_REQUEST)
            
            temp_reg = serializer.save()
            
            # Send OTP via Email
            send_mail(
                subject='OffCity Account Verification OTP',
                message=f'Your OffCity OTP for registration is: {temp_reg.otp}. It is valid for 15 minutes.',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[temp_reg.email],
                fail_silently=False,
            )
            
            return Response({
                "message": "OTP sent successfully to your email.",
                "email": temp_reg.email
            }, status=status.HTTP_201_CREATED)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class VerifyOTPView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            
            try:
                temp_reg = TemporaryRegistration.objects.get(email=email)
            except TemporaryRegistration.DoesNotExist:
                return Response({"error": "Registration data not found."}, status=status.HTTP_404_NOT_FOUND)
                
            if timezone.now() > temp_reg.expires_at:
                temp_reg.delete()
                return Response({"error": "OTP has expired. Please register again."}, status=status.HTTP_400_BAD_REQUEST)
                
            if temp_reg.otp != otp:
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
                
            # Step 1: Create Main User
            user = CustomShopUser.objects.create(
                email=temp_reg.email,
                password=temp_reg.password_hash,
                is_shop_owner=True
            )
            
            # Step 2: Create Shop Profile
            Shop.objects.create(
                owner=user,
                owner_name=temp_reg.owner_name,
                business_name=temp_reg.business_name,
                phone_number=temp_reg.phone_number
            )
            
            # Step 3: Delete Temporary Data
            temp_reg.delete()
            
            # Step 4: Generate JWT Tokens
            tokens = get_tokens_for_user(user)
            
            # Step 5: JSON Response undakkunnu (Ithil token illa)
            response = Response({
                "message": "Registration verified successfully."
            }, status=status.HTTP_200_OK)
            
            # Step 6: Tokens Cookie aayi set cheyyunnu
            # httponly=True aayathu kondu JS vazhi aarkkum ithu moshtikkan pattilla
            response.set_cookie(
                key='access_token',
                value=tokens['access'],
                httponly=True,
                secure=False, # Live server-il (HTTPS) ithu True aakkanam
                samesite='Lax',
                max_age=3600 # 1 hour validity
            )
            response.set_cookie(
                key='refresh_token',
                value=tokens['refresh'],
                httponly=True,
                secure=False, 
                samesite='Lax',
                max_age=7 * 24 * 3600 # 7 days validity
            )
            
            return response
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            try:
                user = CustomShopUser.objects.get(email=email)
            except CustomShopUser.DoesNotExist:
                return Response({"error": "Invalid login credentials."}, status=status.HTTP_401_UNAUTHORIZED)
                
            if not check_password(password, user.password):
                return Response({"error": "Invalid login credentials."}, status=status.HTTP_401_UNAUTHORIZED)
                
            tokens = get_tokens_for_user(user)
            
            # JSON response-il token kalanju
            response = Response({
                "message": "Login successful.",
                "is_shop_owner": getattr(user, 'is_shop_owner', False)
            }, status=status.HTTP_200_OK)
            
            # Cookies set cheyyunnu
            response.set_cookie(
                key='access_token',
                value=tokens['access'],
                httponly=True,
                secure=False, 
                samesite='Lax',
                max_age=3600
            )
            response.set_cookie(
                key='refresh_token',
                value=tokens['refresh'],
                httponly=True,
                secure=False, 
                samesite='Lax',
                max_age=7 * 24 * 3600
            )
            
            return response
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class CleanupTemporaryRegistrationsView(APIView):
    def get(self, request):
        token = request.query_params.get('token')
        secret = getattr(settings, 'CRON_SECRET_KEY', 'default_secret')
        
        if token != secret:
            raise PermissionDenied("Invalid token. Unauthorized access.")
            
        expired_records = TemporaryRegistration.objects.filter(expires_at__lt=timezone.now())
        deleted_count, _ = expired_records.delete()
        
        return Response({
            "message": "Cleanup executed successfully.",
            "deleted_count": deleted_count
        }, status=status.HTTP_200_OK)
    
class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            try:
                user = CustomShopUser.objects.get(email=email)
            except CustomShopUser.DoesNotExist:
                # Security feature: Don't tell hackers if email exists or not
                return Response({"message": "If this email is registered, an OTP has been sent."}, status=status.HTTP_200_OK)
            
            # Generate 6-digit OTP
            otp_code = str(random.randint(100000, 999999))
            
            # Update existing OTP or Create a new one for this user
            reset_obj, created = PasswordResetOTP.objects.update_or_create(
                user=user,
                defaults={'otp': otp_code, 'expires_at': timezone.now() + timedelta(minutes=10)}
            )
            
            # Send Email
            send_mail(
                subject='OffCity Password Reset OTP',
                message=f'Your OTP for resetting password is: {otp_code}. It is valid for 10 minutes.',
                from_email=settings.EMAIL_HOST_USER,
                recipient_list=[user.email],
                fail_silently=False,
            )
            
            return Response({"message": "If this email is registered, an OTP has been sent."}, status=status.HTTP_200_OK)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']
            
            try:
                user = CustomShopUser.objects.get(email=email)
                reset_obj = PasswordResetOTP.objects.get(user=user)
            except (CustomShopUser.DoesNotExist, PasswordResetOTP.DoesNotExist):
                return Response({"error": "Invalid request or OTP not generated."}, status=status.HTTP_400_BAD_REQUEST)
                
            # Check if OTP is expired
            if timezone.now() > reset_obj.expires_at:
                reset_obj.delete()
                return Response({"error": "OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
                
            # Check if OTP matches
            if reset_obj.otp != otp:
                return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
                
            # Change the Password
            user.set_password(new_password) 
            user.save()
            
            # Delete OTP after successful reset
            reset_obj.delete()
            
            return Response({"message": "Password has been reset successfully. You can now login."}, status=status.HTTP_200_OK)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class LogoutView(APIView):
    permission_classes = [IsAuthenticated] 

    def post(self, request):
        response = Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
        
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')
        
        return response