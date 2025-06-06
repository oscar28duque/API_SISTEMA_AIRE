from django.shortcuts import render, get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import (
    Usuario, Rol, UsuarioRol, TokenRecuperacion, RegistroIntentoLogin,
    Zona, Estacion, Sensor, Lectura, Alerta, Reporte, DetalleReporte,
    ConfiguracionDashboard, LogActividad
)
from .serializers import (
    UsuarioSerializer, LoginSerializer, UsuarioInfoSerializer,
    RolSerializer, UsuarioRolSerializer, TokenRecuperacionSerializer,
    RegistroIntentoLoginSerializer, SensorSerializer, ZonaSerializer,
    EstacionSerializer, LecturaSerializer, AlertaSerializer
)
import ipaddress
from django.http import HttpRequest
from django.core.mail import send_mail
from django.conf import settings
import secrets
from datetime import timedelta
import logging
import csv
from datetime import datetime
from django.http import HttpResponse

logger = logging.getLogger(__name__)

# Create your views here.

# CRUD Usuarios
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def usuarios(request):
    if request.method == 'GET':
        usuarios = Usuario.objects.all()
        serializer = UsuarioInfoSerializer(usuarios, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = UsuarioSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(UsuarioInfoSerializer(user).data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def usuario_detalle(request, pk):
    usuario = get_object_or_404(Usuario, pk=pk)
    
    if request.method == 'GET':
        serializer = UsuarioInfoSerializer(usuario)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = UsuarioSerializer(usuario, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(UsuarioInfoSerializer(usuario).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        usuario.is_active = False
        usuario.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD Roles
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def roles(request):
    try:
        if request.method == 'GET':
            roles = Rol.objects.filter(is_active=True)
            serializer = RolSerializer(roles, many=True)
            return Response(serializer.data)
        
        elif request.method == 'POST':
            if not request.user.is_staff:
                return Response(
                    {'error': 'No tiene permisos para crear roles'},
                    status=status.HTTP_403_FORBIDDEN
                )
            serializer = RolSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Error en roles: {str(e)}")
        return Response(
            {'error': 'Error al procesar la solicitud de roles'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def rol_detalle(request, pk):
    try:
        rol = Rol.objects.get(pk=pk)
        
        if request.method == 'GET':
            serializer = RolSerializer(rol)
            return Response(serializer.data)
        
        elif request.method == 'PUT':
            if not request.user.is_staff:
                return Response(
                    {'error': 'No tiene permisos para modificar roles'},
                    status=status.HTTP_403_FORBIDDEN
                )
            serializer = RolSerializer(rol, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        elif request.method == 'DELETE':
            if not request.user.is_staff:
                return Response(
                    {'error': 'No tiene permisos para eliminar roles'},
                    status=status.HTTP_403_FORBIDDEN
                )
            rol.is_active = False
            rol.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
    except Rol.DoesNotExist:
        return Response(
            {'error': 'Rol no encontrado'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error en rol_detalle: {str(e)}")
        return Response(
            {'error': 'Error al procesar la solicitud del rol'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# CRUD UsuarioRol
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def usuarios_roles(request):
    try:
        if request.method == 'GET':
            usuarios_roles = UsuarioRol.objects.filter(is_active=True)
            serializer = UsuarioRolSerializer(usuarios_roles, many=True)
            return Response(serializer.data)
        
        elif request.method == 'POST':
            if not request.user.is_staff:
                return Response(
                    {'error': 'No tiene permisos para asignar roles'},
                    status=status.HTTP_403_FORBIDDEN
                )
            serializer = UsuarioRolSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Error en usuarios_roles: {str(e)}")
        return Response(
            {'error': 'Error al procesar la solicitud de usuarios_roles'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def usuario_rol_detalle(request, pk):
    try:
        usuario_rol = UsuarioRol.objects.get(pk=pk)
        
        if request.method == 'GET':
            serializer = UsuarioRolSerializer(usuario_rol)
            return Response(serializer.data)
        
        elif request.method == 'PUT':
            if not request.user.is_staff:
                return Response(
                    {'error': 'No tiene permisos para modificar asignaciones de roles'},
                    status=status.HTTP_403_FORBIDDEN
                )
            serializer = UsuarioRolSerializer(usuario_rol, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        elif request.method == 'DELETE':
            if not request.user.is_staff:
                return Response(
                    {'error': 'No tiene permisos para eliminar asignaciones de roles'},
                    status=status.HTTP_403_FORBIDDEN
                )
            usuario_rol.is_active = False
            usuario_rol.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
    except UsuarioRol.DoesNotExist:
        return Response(
            {'error': 'UsuarioRol no encontrado'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error en usuario_rol_detalle: {str(e)}")
        return Response(
            {'error': 'Error al procesar la solicitud del usuario_rol'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# CRUD TokenRecuperacion
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def tokens_recuperacion(request):
    if request.method == 'GET':
        tokens = TokenRecuperacion.objects.all()
        serializer = TokenRecuperacionSerializer(tokens, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = TokenRecuperacionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def token_recuperacion_detalle(request, pk):
    token = get_object_or_404(TokenRecuperacion, pk=pk)
    
    if request.method == 'GET':
        serializer = TokenRecuperacionSerializer(token)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = TokenRecuperacionSerializer(token, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        token.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD RegistroIntentoLogin
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def intentos_login(request):
    intentos = RegistroIntentoLogin.objects.all()
    serializer = RegistroIntentoLoginSerializer(intentos, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def intento_login_detalle(request, pk):
    intento = get_object_or_404(RegistroIntentoLogin, pk=pk)
    serializer = RegistroIntentoLoginSerializer(intento)
    return Response(serializer.data)

# Autenticación
@api_view(['POST'])
@permission_classes([AllowAny])
def registro_usuario(request):
    try:
        serializer = UsuarioSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'message': 'Usuario registrado exitosamente',
                'user': UsuarioInfoSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Error en registro_usuario: {str(e)}")
        return Response(
            {'error': 'Error al registrar usuario'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def login_usuario(request):
    try:
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    return Response(
                        {'error': 'La cuenta está desactivada'},
                        status=status.HTTP_403_FORBIDDEN
                    )
                
                refresh = RefreshToken.for_user(user)
                RegistroIntentoLogin.objects.create(
                    usuario=user,
                    email_ingresado=user.email,
                    exitoso=True,
                    ip=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT')
                )
                
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': UsuarioInfoSerializer(user).data
                })
            
            RegistroIntentoLogin.objects.create(
                email_ingresado=username,
                exitoso=False,
                ip=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT')
            )
            return Response(
                {'error': 'Credenciales inválidas'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f"Error en login_usuario: {str(e)}")
        return Response(
            {'error': 'Error al iniciar sesión'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def usuario_actual(request):
    try:
        serializer = UsuarioInfoSerializer(request.user)
        return Response(serializer.data)
    except Exception as e:
        logger.error(f"Error en usuario_actual: {str(e)}")
        return Response(
            {'error': 'Error al obtener información del usuario'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Recuperación de Contraseña
@api_view(['POST'])
@permission_classes([AllowAny])
def solicitar_recuperacion_password(request):
    try:
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email es requerido'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = Usuario.objects.get(email=email)
        except Usuario.DoesNotExist:
            return Response(
                {'error': 'No existe un usuario con este email'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Desactivar tokens anteriores
        TokenRecuperacion.objects.filter(
            usuario=user,
            is_active=True
        ).update(is_active=False)
        
        token = TokenRecuperacion.objects.create(
            usuario=user,
            fecha_expiracion=timezone.now() + timezone.timedelta(hours=24)
        )
        
        # Enviar email con el token
        mensaje = f'Tu token de recuperación es: {token.token}'
        print("\n" + "="*50)
        print("TOKEN DE RECUPERACIÓN:")
        print(mensaje)
        print("="*50 + "\n")
        
        send_mail(
            'Recuperación de contraseña',
            mensaje,
            settings.EMAIL_HOST_USER,
            [email],
            fail_silently=False,
        )
        
        return Response({
            'message': 'Token de recuperación enviado al email'
        })
    except Exception as e:
        logger.error(f"Error en solicitar_recuperacion_password: {str(e)}")
        return Response(
            {'error': 'Error al procesar la solicitud de recuperación'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def verificar_token_recuperacion(request):
    try:
        token = request.data.get('token')
        if not token:
            return Response(
                {'error': 'Token es requerido'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            token_recuperacion = TokenRecuperacion.objects.get(
                token=token,
                is_active=True,
                fecha_expiracion__gt=timezone.now()
            )
            return Response({
                'message': 'Token válido',
                'usuario_id': token_recuperacion.usuario.id
            })
        except TokenRecuperacion.DoesNotExist:
            return Response(
                {'error': 'Token inválido o expirado'},
                status=status.HTTP_400_BAD_REQUEST
            )
    except Exception as e:
        logger.error(f"Error en verificar_token_recuperacion: {str(e)}")
        return Response(
            {'error': 'Error al verificar el token'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def cambiar_password(request):
    try:
        token = request.data.get('token')
        nueva_password = request.data.get('nueva_password')
        
        if not token or not nueva_password:
            return Response(
                {'error': 'Token y nueva contraseña son requeridos'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            token_recuperacion = TokenRecuperacion.objects.get(
                token=token,
                is_active=True,
                fecha_expiracion__gt=timezone.now()
            )
            
            user = token_recuperacion.usuario
            user.set_password(nueva_password)
            user.save()
            
            token_recuperacion.is_active = False
            token_recuperacion.save()
            
            return Response({
                'message': 'Contraseña actualizada exitosamente'
            })
        except TokenRecuperacion.DoesNotExist:
            return Response(
                {'error': 'Token inválido o expirado'},
                status=status.HTTP_400_BAD_REQUEST
            )
    except Exception as e:
        logger.error(f"Error en cambiar_password: {str(e)}")
        return Response(
            {'error': 'Error al cambiar la contraseña'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

# Listados generales
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_usuarios(request):
    usuarios = Usuario.objects.all()
    serializer = UsuarioInfoSerializer(usuarios, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_roles(request):
    roles = Rol.objects.all()
    serializer = RolSerializer(roles, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_zonas(request):
    zonas = Zona.objects.all()
    serializer = ZonaSerializer(zonas, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_estaciones(request):
    estaciones = Estacion.objects.all()
    serializer = EstacionSerializer(estaciones, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_sensores(request):
    sensores = Sensor.objects.all()
    serializer = SensorSerializer(sensores, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_lecturas(request):
    lecturas = Lectura.objects.all()
    serializer = LecturaSerializer(lecturas, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_alertas(request):
    alertas = Alerta.objects.all()
    serializer = AlertaSerializer(alertas, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_reportes(request):
    reportes = Reporte.objects.all()
    serializer = ReporteSerializer(reportes, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_configuraciones_dashboard(request):
    configuraciones = ConfiguracionDashboard.objects.all()
    serializer = ConfiguracionDashboardSerializer(configuraciones, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def listar_logs_actividad(request):
    logs = LogActividad.objects.all()
    serializer = LogActividadSerializer(logs, many=True)
    return Response(serializer.data)

# Detalles específicos
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_usuario(request, pk):
    usuario = get_object_or_404(Usuario, pk=pk)
    serializer = UsuarioInfoSerializer(usuario)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_rol(request, pk):
    rol = get_object_or_404(Rol, pk=pk)
    serializer = RolSerializer(rol)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_zona(request, pk):
    zona = get_object_or_404(Zona, pk=pk)
    serializer = ZonaSerializer(zona)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_estacion(request, pk):
    estacion = get_object_or_404(Estacion, pk=pk)
    serializer = EstacionSerializer(estacion)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_sensor(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    serializer = SensorSerializer(sensor)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_lectura(request, pk):
    lectura = get_object_or_404(Lectura, pk=pk)
    serializer = LecturaSerializer(lectura)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_alerta(request, pk):
    alerta = get_object_or_404(Alerta, pk=pk)
    serializer = AlertaSerializer(alerta)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_reporte(request, pk):
    reporte = get_object_or_404(Reporte, pk=pk)
    serializer = ReporteSerializer(reporte)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_configuracion_dashboard(request, pk):
    configuracion = get_object_or_404(ConfiguracionDashboard, pk=pk)
    serializer = ConfiguracionDashboardSerializer(configuracion)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def detalle_log_actividad(request, pk):
    log = get_object_or_404(LogActividad, pk=pk)
    serializer = LogActividadSerializer(log)
    return Response(serializer.data)

# CRUD Zonas
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def zonas(request):
    if request.method == 'GET':
        zonas = Zona.objects.all()
        serializer = ZonaSerializer(zonas, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = ZonaSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def zona_detalle(request, pk):
    zona = get_object_or_404(Zona, pk=pk)
    
    if request.method == 'GET':
        serializer = ZonaSerializer(zona)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = ZonaSerializer(zona, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        zona.is_active = False
        zona.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD Estaciones
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def estaciones(request):
    if request.method == 'GET':
        estaciones = Estacion.objects.all()
        serializer = EstacionSerializer(estaciones, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = EstacionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def estacion_detalle(request, pk):
    estacion = get_object_or_404(Estacion, pk=pk)
    
    if request.method == 'GET':
        serializer = EstacionSerializer(estacion)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = EstacionSerializer(estacion, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        estacion.is_active = False
        estacion.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD Sensores
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def sensores(request):
    if request.method == 'GET':
        sensores = Sensor.objects.all()
        serializer = SensorSerializer(sensores, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = SensorSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def sensor_detalle(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    
    if request.method == 'GET':
        serializer = SensorSerializer(sensor)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = SensorSerializer(sensor, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        sensor.is_active = False
        sensor.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def calibrar_sensor(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    sensor.fecha_ultima_calibracion = timezone.now().date()
    sensor.estado = 'activo'
    sensor.save()
    serializer = SensorSerializer(sensor)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def lecturas_sensor(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    lecturas = Lectura.objects.filter(sensor=sensor)
    serializer = LecturaSerializer(lecturas, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def alertas_sensor(request, pk):
    sensor = get_object_or_404(Sensor, pk=pk)
    alertas = Alerta.objects.filter(sensor=sensor)
    serializer = AlertaSerializer(alertas, many=True)
    return Response(serializer.data)

# CRUD Lecturas
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def lecturas(request):
    if request.method == 'GET':
        lecturas = Lectura.objects.all()
        serializer = LecturaSerializer(lecturas, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = LecturaSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def lectura_detalle(request, pk):
    lectura = get_object_or_404(Lectura, pk=pk)
    
    if request.method == 'GET':
        serializer = LecturaSerializer(lectura)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = LecturaSerializer(lectura, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        lectura.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD Alertas
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def alertas(request):
    if request.method == 'GET':
        alertas = Alerta.objects.all()
        serializer = AlertaSerializer(alertas, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = AlertaSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def alerta_detalle(request, pk):
    alerta = get_object_or_404(Alerta, pk=pk)
    
    if request.method == 'GET':
        serializer = AlertaSerializer(alerta)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = AlertaSerializer(alerta, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        alerta.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD Reportes
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def reportes(request):
    if request.method == 'GET':
        reportes = Reporte.objects.all()
        serializer = ReporteSerializer(reportes, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = ReporteSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def reporte_detalle(request, pk):
    reporte = get_object_or_404(Reporte, pk=pk)
    
    if request.method == 'GET':
        serializer = ReporteSerializer(reporte)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = ReporteSerializer(reporte, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        reporte.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

# CRUD Configuraciones Dashboard
@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def configuraciones_dashboard(request):
    if request.method == 'GET':
        configuraciones = ConfiguracionDashboard.objects.all()
        serializer = ConfiguracionDashboardSerializer(configuraciones, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        serializer = ConfiguracionDashboardSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def configuracion_dashboard_detalle(request, pk):
    configuracion = get_object_or_404(ConfiguracionDashboard, pk=pk)
    
    if request.method == 'GET':
        serializer = ConfiguracionDashboardSerializer(configuracion)
        return Response(serializer.data)
    
    elif request.method == 'PUT':
        serializer = ConfiguracionDashboardSerializer(configuracion, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    elif request.method == 'DELETE':
        configuracion.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def generar_reporte_lecturas(request):
    sensor_id = request.GET.get('sensor')
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')

    if not all([sensor_id, start_date, end_date]):
        return Response(
            {'error': 'Se requieren los parámetros sensor, start_date y end_date'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        sensor = Sensor.objects.get(id=sensor_id)
        start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
        end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
        end_datetime = end_datetime.replace(hour=23, minute=59, second=59)

        lecturas = Lectura.objects.filter(
            sensor=sensor,
            fecha_hora__range=(start_datetime, end_datetime)
        ).order_by('fecha_hora')

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="reporte_sensor_{sensor_id}_{start_date}_{end_date}.csv"'

        writer = csv.writer(response)
        writer.writerow(['ID', 'Sensor', 'Valor', 'Fecha/Hora', 'Calidad del Dato'])

        for lectura in lecturas:
            writer.writerow([
                lectura.id,
                f"{sensor.tipo_sensor} - {sensor.modelo}",
                lectura.valor,
                lectura.fecha_hora,
                lectura.calidad_dato
            ])

        return response

    except Sensor.DoesNotExist:
        return Response(
            {'error': 'Sensor no encontrado'},
            status=status.HTTP_404_NOT_FOUND
        )
    except ValueError:
        return Response(
            {'error': 'Formato de fecha inválido. Use YYYY-MM-DD'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )
