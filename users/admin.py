
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User, UserActivity


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Custom admin interface for User model.
    """
    list_display = ('email', 'first_name', 'last_name', 'role', 'is_active', 'date_joined')
    list_filter = ('role', 'is_active', 'is_staff', 'date_joined')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name', 'phone_number', 'date_of_birth', 'address')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2', 'role'),
        }),
    )


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    """
    Admin interface for UserActivity model.
    """
    list_display = ('user', 'activity_type', 'timestamp', 'ip_address')
    list_filter = ('activity_type', 'timestamp')
    search_fields = ('user__email', 'ip_address')
    readonly_fields = ('timestamp',)
    date_hierarchy = 'timestamp'
    

