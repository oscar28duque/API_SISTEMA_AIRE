from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import Usuario, Rol, UsuarioRol, TokenRecuperacion, RegistroIntentoLogin
from .serializers import (
    UsuarioSerializer, LoginSerializer, UsuarioInfoSerializer,
    RolSerializer, UsuarioRolSerializer, TokenRecuperacionSerializer
)
import ipaddress
from django.http import HttpRequest
from django.core.mail import send_mail
from django.conf import settings
import secrets
from datetime import timedelta

# Create your views here.

# Registro y Autenticación
@api_view(['POST'])
@permission_classes([AllowAny])
def registro_usuario(request):
    serializer = UsuarioSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UsuarioInfoSerializer(user).data,
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_usuario(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        
        # Obtener la IP del cliente
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        # Obtener el User-Agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Intentar autenticar al usuario
        user = authenticate(username=username, password=password)
        
        # Registrar el intento de login
        RegistroIntentoLogin.objects.create(
            usuario=user,
            email_ingresado=username,
            exitoso=user is not None,
            ip=ip,
            user_agent=user_agent
        )
        
        if user:
            if user.estado_cuenta == 'inactivo':
                return Response(
                    {'error': 'Tu cuenta está inactiva. Por favor, contacta al administrador.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            refresh = RefreshToken.for_user(user)
            return Response({
                'user': UsuarioInfoSerializer(user).data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        
        return Response(
            {'error': 'Credenciales inválidas'},
            status=status.HTTP_401_UNAUTHORIZED
        )
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def usuario_actual(request):
    serializer = UsuarioInfoSerializer(request.user)
    return Response(serializer.data)

# Gestión de Roles
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def crear_rol(request):
    serializer = RolSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def asignar_rol_usuario(request):
    serializer = UsuarioRolSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Recuperación de Contraseña
@api_view(['POST'])
@permission_classes([AllowAny])
def solicitar_recuperacion_password(request):
    email = request.data.get('email')
    try:
        user = Usuario.objects.get(email=email)
        token = secrets.token_urlsafe(32)
        TokenRecuperacion.objects.create(
            usuario=user,
            token=token,
            fecha_expiracion=timezone.now() + timedelta(hours=24)
        )
        
        # Enviar email con el token
        send_mail(
            'Recuperación de Contraseña',
            f'Tu token de recuperación es: {token}',
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        
        return Response({'message': 'Se ha enviado un email con las instrucciones'})
    except Usuario.DoesNotExist:
        return Response(
            {'error': 'No existe un usuario con ese email'},
            status=status.HTTP_404_NOT_FOUND
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def resetear_password(request):
    token = request.data.get('token')
    password = request.data.get('password')
    password2 = request.data.get('password2')
    
    if password != password2:
        return Response(
            {'error': 'Las contraseñas no coinciden'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        token_rec = TokenRecuperacion.objects.get(
            token=token,
            is_active=True,
            fecha_expiracion__gt=timezone.now()
        )
        user = token_rec.usuario
        user.set_password(password)
        user.save()
        
        # Desactivar el token
        token_rec.is_active = False
        token_rec.save()
        
        return Response({'message': 'Contraseña actualizada correctamente'})
    except TokenRecuperacion.DoesNotExist:
        return Response(
            {'error': 'Token inválido o expirado'},
            status=status.HTTP_400_BAD_REQUEST
        )

# Registro de Intentos de Login
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def ver_intentos_login(request):
    intentos = RegistroIntentoLogin.objects.filter(usuario=request.user)
    data = [{
        'fecha_hora': intento.fecha_hora,
        'exitoso': intento.exitoso,
        'ip': intento.ip,
        'user_agent': intento.user_agent
    } for intento in intentos]
    return Response(data)
