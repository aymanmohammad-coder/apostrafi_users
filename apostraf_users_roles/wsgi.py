
import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'apostraf_users_roles.settings')

application = get_wsgi_application()
