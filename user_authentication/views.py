from datetime import datetime, timedelta
from django.contrib.auth import login as auth_login, get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView
from django.shortcuts import render
from django.utils import timezone
from knox.models import AuthToken
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from fortressCRM.helper_functions import api_log
from .models import User
from .serializers import RegisterSerializer, VerifyAccountSerializer, LoginSerializer
from .utils import generate_otp, send_verification_email
from knox.auth import TokenAuthentication as knoxAuth
from knox.views import LoginView as KnoxLoginView


class RegisterView(APIView):
    # permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        return render(request, 'registration.html')

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            api_log(msg=f"[this is: Serializers] : {user} saved")
            # Send verification email with OTP
            otp = generate_otp()
            api_log(msg=f"[OTP]: {otp} generated")
            user.otp = otp
            api_log(msg=f"[user.otp] : {user.otp}")
            user.otp_expiry = datetime.now() + timedelta(minutes=5)
            api_log(msg=f"[OTP EXPIRATION]: {user.otp_expiry}")
            user.save()
            api_log(msg=f"[OTP EXPIRATION]: {user.otp_expiry}")
            send_verification_email(user.email, otp)
            return Response(
                {
                    'message': 'Account created successfully. Please verify your email.',
                    "status": status.HTTP_201_CREATED,
                }
            )
        api_log(msg="10")
        msg = api_log(msg=f"{serializer.errors}")
        return Response(
            {
                'message': msg,
                "status": status.HTTP_400_BAD_REQUEST,
            }
        )


class VerifyAccountView(APIView):
    def get(self, request, *args, **kwargs):
        email = request.GET.get('email')
        return render(request, 'email_verification.html', {'email': email})

    def post(self, request, *args, **kwargs):
        serializer = VerifyAccountSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            try:
                user = User.objects.get(email=email)
                api_log(msg=f"user is: {user}")
                if user.otp == otp and user.otp_expiry > timezone.now():
                    user.otp = None
                    user.otp_expiry = None
                    user.save()
                    return Response(
                        {
                            'message': 'Account verified successfully. please proceed to login page.',
                            "status": status.HTTP_200_OK,
                        }
                    )
                else:
                    return Response({'message': 'Invalid OTP or OTP has expired.', 'status': 400}, status=400)
            except User.DoesNotExist:
                return Response({'message': 'User does not exist.', 'status': 400}, status=400)
        else:
            return Response({'message': serializer.errors, 'status': 400}, status=400)


class InitialLoginView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        api_log(msg=f"Initial login view request : {request}")
        return render(request, 'generate_otp.html')

    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        try:
            if email:
                user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': "Email address doesn't exist, please enter a valid email address."}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP and send it to the user
        otp = generate_otp()
        user.otp = otp
        user.otp_expiry = timezone.now() + timedelta(minutes=5)
        user.save()
        send_verification_email(user.email, otp)
        return Response({'message': 'OTP sent to your email.'}, status=status.HTTP_200_OK)


class LoginView(KnoxLoginView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        api_log(msg=f"login view request : {request}")
        return render(request, 'login.html')

    # @csrf_exempt
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        api_log(msg=f"login view serializers : {serializer}")

        if serializer.is_valid():
            user = serializer.validated_data['user']
            api_log(msg=f"login view USER : {user}")

            # Invalidate the OTP
            user.otp = None
            user.otp_expiry = None
            user.save()

            # Create auth token
            _, token = AuthToken.objects.create(user=user)[0]
            api_log(msg=f"login view TOKEN : {token}")

            return Response({'token': token}, status=status.HTTP_200_OK)
        else:
            error = api_log(msg=f"This is a serializers error: {serializer.errors}")
            return Response({'error': error}, status=status.HTTP_400_BAD_REQUEST)


class ProtectedView(GenericAPIView):
    authentication_classes = [knoxAuth]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({'message': 'Hello, authenticated user!'}, status=status.HTTP_200_OK)


class SuccessView(TemplateView):
    template_name = 'success.html'


class HomeView(TemplateView):
    template_name = 'home.html'