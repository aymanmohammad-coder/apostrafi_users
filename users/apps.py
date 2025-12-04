
from django.apps import AppConfig


class UserApiConfig(AppConfig):
    """    
    Defines app name and ready signal for custom user model.
    """
    name = 'users'
    
    def ready(self):
        """        
        Import signals when app is ready.
        """
        import users.signals