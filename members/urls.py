from django.urls import path
from .views import LoginAPI, LogoutAPI, SignupAPI


urlpatterns = [
    path('api/login/', LoginAPI.as_view(), name='login'),
    path('api/logout/', LogoutAPI.as_view(), name='logout'),
    path('api/signup/', SignupAPI.as_view(), name='signup'),
]