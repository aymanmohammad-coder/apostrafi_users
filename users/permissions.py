

from rest_framework import permissions


class IsOwnerOrAdmin(permissions.BasePermission):
      
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner or admin
        return obj == request.user or request.user.is_administrator()


class IsAdminUser(permissions.BasePermission):
    
    
    def has_permission(self, request, view):
        
        return request.user and request.user.is_authenticated and request.user.is_administrator()
    
    def has_object_permission(self, request, view, obj):
        
        return request.user and request.user.is_authenticated and request.user.is_administrator()


class IsOwner(permissions.BasePermission):
    
    def has_object_permission(self, request, view, obj):
        
        return obj == request.user


class IsAdminOrReadOnly(permissions.BasePermission):
    
    def has_permission(self, request, view):
        
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to admins
        return request.user and request.user.is_authenticated and request.user.is_administrator()