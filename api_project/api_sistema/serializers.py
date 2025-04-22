from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import Usuario, Rol, UsuarioRol, TokenRecuperacion, RegistroIntentoLogin
import re

class RolSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rol
        fields = ['id', 'nombre_rol', 'descripcion', 'is_active']
        read_only_fields = ['id']

class UsuarioRolSerializer(serializers.ModelSerializer):
    class Meta:
        model = UsuarioRol
        fields = ['id', 'usuario', 'rol']
        read_only_fields = ['id']

class TokenRecuperacionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TokenRecuperacion
        fields = ['id', 'usuario', 'token', 'fecha_generacion', 'fecha_expiracion', 'is_active']
        read_only_fields = ['id', 'token', 'fecha_generacion', 'fecha_expiracion']

class RegistroIntentoLoginSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegistroIntentoLogin
        fields = ['id', 'usuario', 'email_ingresado', 'fecha_hora', 'exitoso', 'ip', 'user_agent']
        read_only_fields = ['id', 'fecha_hora']

class UsuarioSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    password2 = serializers.CharField(
        write_only=True, 
        required=True,
        style={'input_type': 'password'}
    )
    roles = RolSerializer(many=True, read_only=True)

    class Meta:
        model = Usuario
        fields = [
            'id', 
            'username', 
            'email', 
            'password', 
            'password2', 
            'first_name', 
            'last_name',
            'estado_cuenta',
            'roles',
            'is_active',
            'date_joined'
        ]
        read_only_fields = ['id', 'date_joined']
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'email': {'required': True},
            'username': {'required': True}
        }

    def validate_username(self, value):
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError(
                "El nombre de usuario solo puede contener letras, números y guiones bajos."
            )
        if len(value) < 4:
            raise serializers.ValidationError(
                "El nombre de usuario debe tener al menos 4 caracteres."
            )
        return value

    def validate_email(self, value):
        if Usuario.objects.filter(email=value).exists():
            raise serializers.ValidationError(
                "Este correo electrónico ya está registrado."
            )
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError(
                "La contraseña debe tener al menos 8 caracteres."
            )
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError(
                "La contraseña debe contener al menos una letra mayúscula."
            )
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError(
                "La contraseña debe contener al menos una letra minúscula."
            )
        if not re.search(r'[0-9]', value):
            raise serializers.ValidationError(
                "La contraseña debe contener al menos un número."
            )
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Las contraseñas no coinciden"})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = Usuario.objects.create_user(**validated_data)
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True, style={'input_type': 'password'})

class UsuarioInfoSerializer(serializers.ModelSerializer):
    roles = RolSerializer(many=True, read_only=True)

    class Meta:
        model = Usuario
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'estado_cuenta',
            'roles',
            'is_active',
            'date_joined',
            'last_login'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login'] 