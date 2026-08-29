"""spikes/api/config/wsgi.py: Expose the spike WSGI application.

Related modules: config.settings and config.urls.
"""
import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
application = get_wsgi_application()
