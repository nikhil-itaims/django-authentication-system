from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from django.template.loader import get_template
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError, force_bytes
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.contrib.auth import login, logout
from accounts.models import User
from accounts.utils import Utils
from .serializers import *

''' RegisterView for adding user '''

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data = user)
        serializer.is_valid(raise_exception = True)
        serializer.save()

        return Response(serializer.data, status = status.HTTP_201_CREATED)

''' UserListView for display list of users '''

class UserListView(generics.ListAPIView):
    permission_classes = (IsAuthenticated, )
    queryset = User.objects.all()
    serializer_class = UserSerializer

''' UserDetailsView for list, update and delete particluar user '''

class UserDetailsView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = (IsAuthenticated, )
    queryset = User.objects.all()
    serializer_class = UserSerializer

''' LoginView is managing user login using user's email and password. '''

class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        if 'email' not in request.data or 'password' not in request.data:
            return Response({'msg': 'Credentials missing'}, status=status.HTTP_400_BAD_REQUEST)
        data = request.data
        serializer = self.serializer_class(data=data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        
        if not user:
            raise AuthenticationFailed('Invalid credentials')

        if user is not None:
            refresh = RefreshToken.for_user(user)
            login(request, user)

            return Response({
                'userId': user.id,
                'firstName': user.first_name,
                'lastName': user.last_name,
                'userEmail': user.email,
                'userPhone': user.phone,
                'refreshToken' : str(refresh),
                'accessToken' : str(refresh.access_token)
            }, status=status.HTTP_200_OK)

        return Response(serializer.data, status = status.HTTP_403_FORBIDDEN)

''' LogoutView is for logging out user '''

class LogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception = True)
        serializer.save()
        logout(request)
        return Response({'message': 'User successfully logged out'}, status= status.HTTP_200_OK)

''' Change Password View '''

class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

class RequestPasswordResetEmailView(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(request=request).domain
            relativeLink = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            absurl = f'http://{current_site}{relativeLink}?token={str(token)}'
            context = {
                "fname" : user.first_name,
                "lname": user.last_name,
                "url": absurl
            }
            email_body = get_template('email_templates/forgot-password.html').render(context)
            data = {'email_body': email_body, 'to_email': user.email, 'email_subject': 'Reset your password'}
            Utils.send_email(data)
            return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Email not exists please enter regisetr email.'}, status=status.HTTP_400_BAD_REQUEST)

class PasswordTokenCheckView(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)
