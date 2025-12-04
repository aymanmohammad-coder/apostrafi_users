"""
User models for the User Management System.

Defines custom User model with role-based permissions and related models.
"""

from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import EmailValidator
from django.utils import timezone
from django.core.exceptions import ValidationError
import re


class UserManager(BaseUserManager):
    """
    Custom user manager for creating users and superusers.
    
    Provides methods for creating regular users and superusers
    with proper validation and default values.
    """
    
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and return a regular user with the given email and password.
        
        Args:
            email (str): User's email address
            password (str): User's password
            **extra_fields: Additional user fields
            
        Returns:
            User: Created user instance
            
        Raises:
            ValueError: If email is not provided
        """
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with admin privileges.
        
        Args:
            email (str): Superuser's email address
            password (str): Superuser's password
            **extra_fields: Additional user fields
            
        Returns:
            User: Created superuser instance
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', User.Role.ADMIN)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model with role-based authentication.
    
    Extends Django's AbstractBaseUser and PermissionsMixin
    to provide custom authentication and role management.
    """
    
    class Role(models.TextChoices):
        """
        User role choices.
        
        Defines available roles for users in the system.
        """
        USER = 'USER', 'Regular User'
        ADMIN = 'ADMIN', 'Administrator'
        MODERATOR = 'MODERATOR', 'Moderator'
    
    # Basic user information
    email = models.EmailField(
        unique=True,
        max_length=255,
        validators=[EmailValidator()],
        verbose_name='Email Address',
        help_text='Required. Must be a valid email address.'
    )
    first_name = models.CharField(
        max_length=50,
        verbose_name='First Name',
        help_text='Required. 50 characters or fewer.'
    )
    last_name = models.CharField(
        max_length=50,
        verbose_name='Last Name',
        help_text='Required. 50 characters or fewer.'
    )
    
    # Role and permissions
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.USER,
        verbose_name='User Role',
        help_text='User role determines permissions and access levels.'
    )
    
    # Status flags
    is_active = models.BooleanField(
        default=True,
        verbose_name='Active',
        help_text='Designates whether this user should be treated as active.'
    )
    is_staff = models.BooleanField(
        default=False,
        verbose_name='Staff Status',
        help_text='Designates whether the user can log into the admin site.'
    )
    
    # Timestamps
    date_joined = models.DateTimeField(
        default=timezone.now,
        verbose_name='Date Joined'
    )
    last_updated = models.DateTimeField(
        auto_now=True,
        verbose_name='Last Updated'
    )
    
    # Profile information (optional)
    phone_number = models.CharField(
        max_length=20,
        blank=True,
        null=True,
        verbose_name='Phone Number'
    )
    address = models.TextField(
        blank=True,
        null=True,
        verbose_name='Address',
        max_length=500
    )
    date_of_birth = models.DateField(
        blank=True,
        null=True,
        verbose_name='Date of Birth'
    )
    
    # Manager
    objects = UserManager()
    
    # Authentication field
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    # تغيير أسماء العلاقات العكسية لتجنب التعارض
    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='groups',
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        related_name="custom_user_set",  # تغيير الاسم هنا
        related_query_name="custom_user",
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        related_name="custom_user_set",  # تغيير الاسم هنا
        related_query_name="custom_user",
    )
    
    class Meta:
        """
        Metadata options for the User model.
        """
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['role']),
            models.Index(fields=['is_active']),
            models.Index(fields=['date_joined']),
        ]
    
    def __str__(self):
        """
        String representation of the User.
        
        Returns:
            str: User's full name and email
        """
        return f"{self.get_full_name()} ({self.email})"
    
    def get_full_name(self):
        """
        Get the user's full name.
        
        Returns:
            str: User's first and last name combined
        """
        return f"{self.first_name} {self.last_name}".strip()
    
    def get_short_name(self):
        """
        Get the user's short name.
        
        Returns:
            str: User's first name
        """
        return self.first_name
    
    def has_role(self, role):
        """
        Check if user has a specific role.
        
        Args:
            role (str): Role to check
            
        Returns:
            bool: True if user has the role, False otherwise
        """
        return self.role == role
    
    def is_administrator(self):
        """
        Check if user is an administrator.
        
        Returns:
            bool: True if user is admin, False otherwise
        """
        return self.has_role(self.Role.ADMIN)
    
    def clean(self):
        """
        Validate the model before saving.
        
        Raises:
            ValidationError: If validation fails
        """
        super().clean()
        
        # Email validation
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', self.email):
            raise ValidationError({'email': 'Enter a valid email address.'})
        
        # Name validation
        if not re.match(r'^[A-Za-z\s\'-]+$', self.first_name):
            raise ValidationError({'first_name': 'First name can only contain letters, spaces, hyphens, and apostrophes.'})
        
        if not re.match(r'^[A-Za-z\s\'-]+$', self.last_name):
            ValidationError({'last_name': 'Last name can only contain letters, spaces, hyphens, and apostrophes.'})


class UserActivity(models.Model):
    """
    Model to track user activities and login history.
    
    Stores information about user actions for auditing and monitoring.
    """
    
    class ActivityType(models.TextChoices):
        """
        Types of user activities.
        """
        LOGIN = 'LOGIN', 'User Login'
        LOGOUT = 'LOGOUT', 'User Logout'
        PROFILE_UPDATE = 'PROFILE_UPDATE', 'Profile Updated'
        PASSWORD_CHANGE = 'PASSWORD_CHANGE', 'Password Changed'
        ACCOUNT_DELETION = 'ACCOUNT_DELETION', 'Account Deleted'
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='activities',
        verbose_name='User'
    )
    activity_type = models.CharField(
        max_length=20,
        choices=ActivityType.choices,
        verbose_name='Activity Type'
    )
    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True,
        verbose_name='IP Address'
    )
    user_agent = models.TextField(
        blank=True,
        null=True,
        verbose_name='User Agent'
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Timestamp'
    )
    details = models.JSONField(
        blank=True,
        null=True,
        verbose_name='Activity Details'
    )
    
    class Meta:
        """
        Metadata options for UserActivity model.
        """
        verbose_name = 'User Activity'
        verbose_name_plural = 'User Activities'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['activity_type']),
        ]
    
    def __str__(self):
        """
        String representation of UserActivity.
        
        Returns:
            str: Activity description
        """
        return f"{self.user.email} - {self.get_activity_type_display()} at {self.timestamp}"