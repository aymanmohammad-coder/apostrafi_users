"""
App configuration for user_api application.
"""

from django.apps import AppConfig


class UserApiConfig(AppConfig):
    """
    Configuration class for users app.
    
    Defines app name and ready signal for custom user model.
    """
    name = 'users'
    
    def ready(self):
        """
        App ready method for signal registration.
        
        Import signals when app is ready.
        """
        import users.signals