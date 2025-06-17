import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import MADS.routing  # Your app name is MADS

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MADS.settings')

application = ProtocolTypeRouter({
    'http': get_asgi_application(),
    'websocket': AuthMiddlewareStack(
        URLRouter(
            MADS.routing.websocket_urlpatterns
        )
    ),
})