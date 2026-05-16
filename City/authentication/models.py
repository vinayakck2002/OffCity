from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager 
from django.utils import timezone
from datetime import timedelta
import uuid

class Location(models.Model):
    name = models.CharField(max_length=100, unique=True)  
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name
class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifier
    for authentication instead of usernames.
    """
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)
class CustomShopUser(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None
    email = models.EmailField(unique=True)
    is_shop_owner = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()
    def __str__(self):
        return self.email

class Shop(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.OneToOneField(CustomShopUser, on_delete=models.CASCADE, related_name='shop_details')
    owner_name = models.CharField(max_length=100)
    business_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15)
    logo_path = models.CharField(max_length=255, blank=True, null=True)
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True, related_name='shops')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.business_name

class TemporaryRegistration(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner_name = models.CharField(max_length=100)
    business_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15)
    password_hash = models.CharField(max_length=255)
    otp = models.CharField(max_length=6)
    location = models.ForeignKey(Location, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=15)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.email} - Pending"


class PasswordResetOTP(models.Model):
    user = models.OneToOneField(CustomShopUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def save(self, *args, **kwargs):
        if not self.expires_at:
            # Forgot Password OTP expires in 10 minutes
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Password Reset OTP for {self.user.email}"