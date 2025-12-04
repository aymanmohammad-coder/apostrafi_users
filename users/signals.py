"""
Signal handlers for User model.

Defines post-save and post-delete signals for user operations.
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils import timezone
from .models import User, UserActivity


@receiver(post_save, sender=User)
def user_created_handler(sender, instance, created, **kwargs):
    """
    Handle user creation signal.
    
    Args:
        sender: Model class
        instance: User instance
        created (bool): True if instance was created
        **kwargs: Additional arguments
    """
    if created:
        # Log user creation (if not already logged in view)
        UserActivity.objects.create(
            user=instance,
            activity_type=UserActivity.ActivityType.LOGIN,
            details={'action': 'account_creation'}
        )


@receiver(post_save, sender=User)
def user_updated_handler(sender, instance, created, **kwargs):
    """
    Handle user update signal.
    
    Args:
        sender: Model class
        instance: User instance
        created (bool): True if instance was created
        **kwargs: Additional arguments
    """
    if not created:
        # Update last_updated timestamp is handled in model
        pass