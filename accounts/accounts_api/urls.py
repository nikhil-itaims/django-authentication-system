from django.urls import path
from . import views
from rest_framework_simplejwt import views as jwt_views

urlpatterns = [
    path('login/', views.LoginView.as_view(), name ='login-user'), # Login user and send otp
    path('login/refresh/', jwt_views.TokenRefreshView.as_view(), name ='token-refresh'), # Get access token from resfresh token
    path('logout/', views.LogoutView.as_view(), name = 'logout-user'), # Logout user
    path('register/', views.RegisterView.as_view(), name ='register-user'), # Addding user
    path('users/', views.UserListView.as_view(), name = 'users'), # List of users
    path('users/<int:pk>/', views.UserDetailsView.as_view(), name = 'user'), # Retrieve, update particular user's data or delete user
    path('change-password/<int:id>/', views.ChangePasswordView.as_view(),name='auth_change_password'), # change password
    path('forgot-password/', views.RequestPasswordResetEmailView.as_view(), name='request-reset-email'),
    path('forgot-password/<uidb64>/<token>', views.PasswordTokenCheckView.as_view(), name='password-reset-confirm'),
    path('forgot-password/reset-complete/', views.SetNewPasswordView.as_view(), name='password-reset-complete'),
]