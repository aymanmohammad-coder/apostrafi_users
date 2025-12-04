

from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    UserRegistrationView, UserLoginView, UserProfileView,
    UserListView, UserDetailView, UserActivityView, LogoutView
)

urlpatterns = [
    # Authentication 
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User profile 
    path('profile/', UserProfileView.as_view(), name='profile'),
    
    # User management  (admin only)
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<int:id>/', UserDetailView.as_view(), name='user-detail'),
    
    # Activity logs
    path('activities/', UserActivityView.as_view(), name='user-activities'),
]