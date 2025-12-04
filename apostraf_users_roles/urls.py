
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions


urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/v1/auth/', include('users.urls')),
    

]

# Serve static files in development
if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)