

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.utils.translation import gettext as _
from .models import User, UserActivity

from .validators import password_validator, email_validator, validate_name, validate_phone_number


class UserRegistrationSerializer(serializers.ModelSerializer):
   
    
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        validators=[password_validator],  # استخدام instance الذي تم إنشاؤه
        help_text='Password must be at least 8 characters long, contain at least one digit, one uppercase and one lowercase letter.'
    )
    
    password_confirmation = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text='Enter the same password as above for verification.'
    )
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'password', 'password_confirmation',
            'first_name', 'last_name', 'phone_number',
            'date_of_birth', 'address', 'role', 'date_joined'
        ]
        read_only_fields = ['id', 'date_joined', 'role']
        extra_kwargs = {
            'email': {
                'required': True,
                'validators': [email_validator]  # استخدام instance هنا أيضاً
            },
            'first_name': {
                'required': True,
                'validators': [validate_name]
            },
            'last_name': {
                'required': True,
                'validators': [validate_name]
            },
            'phone_number': {
                'validators': [validate_phone_number]
            }
        }
    
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                _('A user with this email already exists.')
            )
        return value.lower()
    
    def validate(self, data):
        if data.get('password') != data.get('password_confirmation'):
            raise serializers.ValidationError({
                'password_confirmation': _('Passwords do not match.')
            })
        
        if data.get('date_of_birth'):
            from datetime import date
            if data['date_of_birth'] > date.today():
                raise serializers.ValidationError({
                    'date_of_birth': _('Date of birth cannot be in the future.')
                })
        
        return data
    
    def create(self, validated_data):
        validated_data.pop('password_confirmation', None)
        
        user = User.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_number=validated_data.get('phone_number'),
            date_of_birth=validated_data.get('date_of_birth'),
            address=validated_data.get('address'),
            role=User.Role.USER
        )
        
        return user


class UserUpdateSerializer(serializers.ModelSerializer):
    
    
    current_password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'},
        help_text='Current password is required for certain updates'
    )
    
    new_password = serializers.CharField(
        write_only=True,
        required=False,
        style={'input_type': 'password'},
        validators=[password_validator],  # استخدام نفس instance
        help_text='New password (if changing)'
    )
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'phone_number',
            'date_of_birth', 'address', 'current_password',
            'new_password'
        ]
        extra_kwargs = {
            'first_name': {'validators': [validate_name]},
            'last_name': {'validators': [validate_name]},
            'phone_number': {'validators': [validate_phone_number]}
        }
    
    def validate(self, data):
        user = self.instance
        request = self.context.get('request')
        
        if request and request.user != user:
            raise serializers.ValidationError(
                _('You can only update your own profile.')
            )
        
        if data.get('date_of_birth'):
            from datetime import date
            if data['date_of_birth'] > date.today():
                raise serializers.ValidationError({
                    'date_of_birth': _('Date of birth cannot be in the future.')
                })
        
        return data
    
    def update(self, instance, validated_data):
        current_password = validated_data.pop('current_password', None)
        new_password = validated_data.pop('new_password', None)
        
        if new_password:
            if not current_password:
                raise serializers.ValidationError({
                    'current_password': _('Current password is required to set a new password.')
                })
            
            if not instance.check_password(current_password):
                raise serializers.ValidationError({
                    'current_password': _('Current password is incorrect.')
                })
            
            instance.set_password(new_password)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance


class UserLoginSerializer(serializers.Serializer):
    
    email = serializers.EmailField(
        required=True,
        help_text='User email address'
    )
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text='User password'
    )
    
    def validate(self, data):
        
        email = data.get('email')
        password = data.get('password')
        #print('email: ',email,'password: ',password)
        if email and password:
            # Authenticate user
            user = authenticate(
                request=self.context.get('request'),
                email=email,
                password=password
            )
            
            if not user:
                raise serializers.ValidationError(
                    _('Invalid email or password.')
                )
            
            if not user.is_active:
                raise serializers.ValidationError(
                    _('User account is disabled.')
                )
            
            data['user'] = user
        else:
            raise serializers.ValidationError(
                _('Must include "email" and "password".')
            )
        
        return data


class UserSerializer(serializers.ModelSerializer):
    
    
    full_name = serializers.SerializerMethodField()
    role_display = serializers.CharField(
        source='get_role_display',
        read_only=True
    )
    
    class Meta:
        
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'role', 'role_display', 'phone_number', 'date_of_birth',
            'address', 'is_active', 'date_joined', 'last_updated'
        ]
        read_only_fields = [
            'id', 'email', 'date_joined', 'last_updated', 'role'
        ]
    
    def get_full_name(self, obj):
        
        return obj.get_full_name()



class UserActivitySerializer(serializers.ModelSerializer):
    
    activity_type_display = serializers.CharField(
        source='get_activity_type_display',
        read_only=True
    )
    user_email = serializers.EmailField(
        source='user.email',
        read_only=True
    )
    
    class Meta:
       
        model = UserActivity
        fields = [
            'id', 'user', 'user_email', 'activity_type',
            'activity_type_display', 'ip_address', 'user_agent',
            'timestamp', 'details'
        ]
        read_only_fields = fields