from rest_framework import generics, permissions, status, viewsets
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.utils import timezone
from django.shortcuts import get_object_or_404

from .models import User, UserActivity
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer,
    UserSerializer, UserUpdateSerializer, UserActivitySerializer
)
from .permissions import IsOwnerOrAdmin, IsAdminUser


class UserRegistrationView(generics.CreateAPIView):

    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Log registration activity
        UserActivity.objects.create(
            user=user,
            activity_type=UserActivity.ActivityType.LOGIN,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'action': 'registration'}
        )
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        response_data = {
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            },
            'message': 'User registered successfully.'
        }
        
        return Response(response_data, status=status.HTTP_201_CREATED)
    
    def get_client_ip(self, request):
       
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserLoginView(TokenObtainPairView):
    
    
    serializer_class = UserLoginSerializer
    
    def post(self, request, *args, **kwargs):
    
        serializer = self.get_serializer(data=request.data)
        
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Log login activity
            UserActivity.objects.create(
                user=user,
                activity_type=UserActivity.ActivityType.LOGIN,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'action': 'login'}
            )
            
            # Generate tokens using parent class
            token_serializer = TokenObtainPairSerializer(data=request.data)
            token_serializer.is_valid(raise_exception=True)
            
            response_data = {
                'user': UserSerializer(user).data,
                'tokens': token_serializer.validated_data,
                'message': 'Login successful.'
            }
            
            return Response(response_data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserProfileView(generics.RetrieveUpdateDestroyAPIView):
    
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrAdmin]
    
    def get_object(self):
      
        return self.request.user
    
    def get_serializer_class(self):
      
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserSerializer
    
    def retrieve(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user)
        return Response(serializer.data)
    
    def update(self, request, *args, **kwargs):
        
        partial = kwargs.pop('partial', False)
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        
        # Log profile update activity
        if serializer.validated_data:
            UserActivity.objects.create(
                user=user,
                activity_type=UserActivity.ActivityType.PROFILE_UPDATE,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'updated_fields': list(serializer.validated_data.keys())}
            )
        
        self.perform_update(serializer)
        
        return Response(UserSerializer(user).data)
    
    def destroy(self, request, *args, **kwargs):
        
        user = self.get_object()
        
        # Log account deletion activity
        UserActivity.objects.create(
            user=user,
            activity_type=UserActivity.ActivityType.ACCOUNT_DELETION,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'action': 'account_deletion'}
        )
        
        # Deactivate instead of delete for data retention
        user.is_active = False
        user.email = f"deleted_{user.id}_{user.email}"
        user.save()
        
        return Response(
            {'message': 'User account has been deactivated.'},
            status=status.HTTP_200_OK
        )
    
    def get_client_ip(self, request):
        
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserListView(generics.ListAPIView):
    
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
       
        user = self.request.user
        
        if user.is_administrator():
            # Admins can see all users
            return User.objects.all().order_by('-date_joined')
        else:
            # Regular users can only see themselves
            return User.objects.filter(id=user.id)
    
    def list(self, request, *args, **kwargs):
       
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        
        response_data = {
            'count': queryset.count(),
            'users': serializer.data
        }
        
        return Response(response_data)


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    lookup_field = 'id'
    
    def get_serializer_class(self):
        
        if self.request.method in ['PUT', 'PATCH']:
            return UserUpdateSerializer
        return UserSerializer
    
    def destroy(self, request, *args, **kwargs):
        
        user = self.get_object()
        
        # Don't allow self-deletion for admin
        if user == request.user:
            return Response(
                {'error': 'Admins cannot delete their own account via this endpoint.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Log account deletion activity
        UserActivity.objects.create(
            user=user,
            activity_type=UserActivity.ActivityType.ACCOUNT_DELETION,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'action': 'admin_deletion', 'admin': request.user.email}
        )
        
        # Deactivate instead of delete
        user.is_active = False
        user.email = f"deleted_{user.id}_{user.email}"
        user.save()
        
        return Response(
            {'message': f'User {user.email} has been deactivated.'},
            status=status.HTTP_200_OK
        )
    
    def get_client_ip(self, request):
        
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserActivityView(generics.ListAPIView):
    
    
    serializer_class = UserActivitySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        
        user = self.request.user
        
        if user.is_administrator():
            # Admins can see all activity logs
            return UserActivity.objects.all().order_by('-timestamp')
        else:
            # Regular users can only see their own activity logs
            return UserActivity.objects.filter(user=user).order_by('-timestamp')


class LogoutView(APIView):
    
    
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        
        try:
            refresh_token = request.data.get('refresh')
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Log logout activity
            UserActivity.objects.create(
                user=request.user,
                activity_type=UserActivity.ActivityType.LOGOUT,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                details={'action': 'logout'}
            )
            
            return Response(
                {'message': 'Successfully logged out.'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def get_client_ip(self, request):
        
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip