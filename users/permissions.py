"""
Custom permission classes for User API.

Defines permission rules for different user roles and actions.
"""

from rest_framework import permissions


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission to allow users to edit their own profile or admins to edit any profile.
    
    Users can only modify their own data unless they are administrators.
    """
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission to access the object.
        
        Args:
            request: HTTP request object
            view: API view
            obj: Object being accessed
            
        Returns:
            bool: True if permission granted, False otherwise
        """
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to the owner or admin
        return obj == request.user or request.user.is_administrator()


class IsAdminUser(permissions.BasePermission):
    """
    Permission to allow access only to administrator users.
    
    Restricts access to users with ADMIN role.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has admin permission.
        
        Args:
            request: HTTP request object
            view: API view
            
        Returns:
            bool: True if user is admin, False otherwise
        """
        return request.user and request.user.is_authenticated and request.user.is_administrator()
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user has permission to access the object.
        
        Args:
            request: HTTP request object
            view: API view
            obj: Object being accessed
            
        Returns:
            bool: True if user is admin, False otherwise
        """
        return request.user and request.user.is_authenticated and request.user.is_administrator()


class IsOwner(permissions.BasePermission):
    """
    Permission to allow access only to the object owner.
    
    Users can only access their own data.
    """
    
    def has_object_permission(self, request, view, obj):
        """
        Check if user is the owner of the object.
        
        Args:
            request: HTTP request object
            view: API view
            obj: Object being accessed
            
        Returns:
            bool: True if user is owner, False otherwise
        """
        return obj == request.user


class IsAdminOrReadOnly(permissions.BasePermission):
    """
    Permission to allow admins full access and others read-only access.
    
    Admins can perform any action, while regular users can only read.
    """
    
    def has_permission(self, request, view):
        """
        Check if user has permission for the request.
        
        Args:
            request: HTTP request object
            view: API view
            
        Returns:
            bool: True if permission granted, False otherwise
        """
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions are only allowed to admins
        return request.user and request.user.is_authenticated and request.user.is_administrator()