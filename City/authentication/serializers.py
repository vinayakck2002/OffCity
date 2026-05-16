from rest_framework import serializers
from django.contrib.auth.hashers import make_password
import random
from .models import *

class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ['id', 'name','is_active']
class RegisterSerializer(serializers.Serializer):
    owner_name = serializers.CharField(max_length=100)
    business_name = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    phone_number = serializers.CharField(max_length=15)
    password = serializers.CharField(write_only=True)
    location_id = serializers.IntegerField(write_only=True, required=True) 
    def create(self, validated_data):
        # Generate a 6-digit random OTP
        otp_code = str(random.randint(100000, 999999))
        
        # Hash the plain text password
        hashed_pw = make_password(validated_data['password'])

        # Remove any existing pending registration for this email
        TemporaryRegistration.objects.filter(email=validated_data['email']).delete()
        location_obj = validated_data.get('location', None)

        # Create temporary record
        temp_user = TemporaryRegistration.objects.create(
            owner_name=validated_data['owner_name'],
            business_name=validated_data['business_name'],
            email=validated_data['email'],
            phone_number=validated_data['phone_number'],
            password_hash=hashed_pw,
            otp=otp_code,
            location=location_obj
        )
        return temp_user

class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)


class ShopSerializer(serializers.ModelSerializer):
    location = LocationSerializer(read_only=True)

    class Meta:
        model = Shop
        fields = ['id', 'owner_name', 'business_name', 'email', 'phone_number', 'location']



