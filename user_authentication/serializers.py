import datetime
from django.utils import timezone
from rest_framework import serializers
from fortressCRM.helper_functions import api_log
from .models import User
from django.utils.translation import gettext as _


class RegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ['email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['email'],  # Setting email as username
            email=validated_data['email'],  # Assigning email field
            password=validated_data['password']
        )
        return user


class VerifyAccountSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()


# User = get_user_model()


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        api_log(msg=f"email address from user input: {email}")
        otp = data.get('otp')

        # Logging the initial validation step
        api_log(msg="Starting validation")

        # Check if email exists
        if email and otp:
            try:
                user = User.objects.get(email=email)
                api_log(msg=f"User's email address from DB: {user}")
            except User.DoesNotExist:
                api_log(msg="Email does not exist.")
                msg = _('User with this email does not exist.')

                raise serializers.ValidationError(msg, code='authorization')

            if user.otp == otp and isinstance(user.otp_expiry, datetime.datetime) and user.otp_expiry > timezone.now():
                data['user'] = user  # Return the User object
                return data

            else:
                msg = _('Invalid OTP or OTP has expired.')
                raise serializers.ValidationError(msg, code='authorization')

        else:
            msg = _('Must include "email" and "otp".')
            raise serializers.ValidationError(msg, code='authorization')
