"""spikes/api/config/asgi.py: Expose the spike ASGI application.

Related modules: config.settings and config.urls.
"""
import os
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
application = get_asgi_application()
