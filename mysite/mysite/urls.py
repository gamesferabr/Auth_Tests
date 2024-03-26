from django.contrib import admin
from django.urls import path,include
from ninja import NinjaAPI
from apptest.views import router

api = NinjaAPI()

api.add_router("/apptest", router, tags=["auth"])

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", api.urls),
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider')),
]