from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import Usuario, Rol, UsuarioRol, TokenRecuperacion, RegistroIntentoLogin, Sensor, Zona, Estacion, Lectura, Alerta
import re
import logging

logger = logging.getLogger(__name__)

class RolSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rol
        fields = ['id', 'nombre_rol', 'descripcion', 'is_active']
        read_only_fields = ['id']

    def validate_nombre_rol(self, value):
        try:
            if not re.match(r'^[a-zA-Z0-9_]+$', value):
                raise serializers.ValidationError(
                    "El nombre del rol solo puede contener letras, números y guiones bajos."
                )
            if len(value) < 3:
                raise serializers.ValidationError(
                    "El nombre del rol debe tener al menos 3 caracteres."
                )
            if Rol.objects.filter(nombre_rol=value).exists():
                raise serializers.ValidationError(
                    "Ya existe un rol con este nombre."
                )
            return value
        except Exception as e:
            logger.error(f"Error en validación de nombre_rol: {str(e)}")
            raise serializers.ValidationError("Error al validar el nombre del rol")

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
            'id', 'username', 'email', 'password', 'password2',
            'first_name', 'last_name', 'estado_cuenta', 'roles',
            'is_active'
        ]
        read_only_fields = ['id']
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True}
        }

    def validate_username(self, value):
        try:
            if not re.match(r'^[a-zA-Z0-9_]+$', value):
                raise serializers.ValidationError(
                    "El nombre de usuario solo puede contener letras, números y guiones bajos."
                )
            if len(value) < 4:
                raise serializers.ValidationError(
                    "El nombre de usuario debe tener al menos 4 caracteres."
                )
            if Usuario.objects.filter(username=value).exists():
                raise serializers.ValidationError(
                    "Este nombre de usuario ya está en uso."
                )
            return value
        except Exception as e:
            logger.error(f"Error en validación de username: {str(e)}")
            raise serializers.ValidationError("Error al validar el nombre de usuario")

    def validate_email(self, value):
        try:
            if not value:
                raise serializers.ValidationError("El email es requerido")
            if Usuario.objects.filter(email=value).exists():
                raise serializers.ValidationError(
                    "Este correo electrónico ya está registrado."
                )
            return value
        except Exception as e:
            logger.error(f"Error en validación de email: {str(e)}")
            raise serializers.ValidationError("Error al validar el email")

    def validate_password(self, value):
        try:
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
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
                raise serializers.ValidationError(
                    "La contraseña debe contener al menos un carácter especial."
                )
            return value
        except Exception as e:
            logger.error(f"Error en validación de password: {str(e)}")
            raise serializers.ValidationError("Error al validar la contraseña")

    def validate(self, data):
        try:
            if data['password'] != data['password2']:
                raise serializers.ValidationError("Las contraseñas no coinciden")
            return data
        except Exception as e:
            logger.error(f"Error en validación general: {str(e)}")
            raise serializers.ValidationError("Error en la validación de datos")

    def create(self, validated_data):
        try:
            validated_data.pop('password2')
            user = Usuario.objects.create_user(**validated_data)
            return user
        except Exception as e:
            logger.error(f"Error al crear usuario: {str(e)}")
            raise serializers.ValidationError("Error al crear el usuario")

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )

    def validate(self, data):
        try:
            if not data.get('username') or not data.get('password'):
                raise serializers.ValidationError("Usuario y contraseña son requeridos")
            return data
        except Exception as e:
            logger.error(f"Error en validación de login: {str(e)}")
            raise serializers.ValidationError("Error en la validación de credenciales")

class UsuarioInfoSerializer(serializers.ModelSerializer):
    roles = RolSerializer(many=True, read_only=True)

    class Meta:
        model = Usuario
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'estado_cuenta', 'roles', 'is_active'
        ]
        read_only_fields = ['id']

class UsuarioRolSerializer(serializers.ModelSerializer):
    usuario = UsuarioInfoSerializer(read_only=True)
    rol = RolSerializer(read_only=True)
    usuario_id = serializers.PrimaryKeyRelatedField(
        queryset=Usuario.objects.all(),
        source='usuario',
        write_only=True
    )
    rol_id = serializers.PrimaryKeyRelatedField(
        queryset=Rol.objects.all(),
        source='rol',
        write_only=True
    )

    class Meta:
        model = UsuarioRol
        fields = ['id', 'usuario', 'rol', 'usuario_id', 'rol_id']
        read_only_fields = ['id']

    def validate(self, data):
        try:
            usuario = data.get('usuario')
            rol = data.get('rol')
            
            if UsuarioRol.objects.filter(usuario=usuario, rol=rol).exists():
                raise serializers.ValidationError(
                    "Este usuario ya tiene asignado este rol."
                )
            return data
        except Exception as e:
            logger.error(f"Error en validación de UsuarioRol: {str(e)}")
            raise serializers.ValidationError("Error al validar la asignación de rol")

class TokenRecuperacionSerializer(serializers.ModelSerializer):
    usuario = UsuarioInfoSerializer(read_only=True)
    usuario_id = serializers.PrimaryKeyRelatedField(
        queryset=Usuario.objects.all(),
        source='usuario',
        write_only=True
    )

    class Meta:
        model = TokenRecuperacion
        fields = ['id', 'usuario', 'usuario_id', 'token', 'fecha_expiracion', 'is_active']
        read_only_fields = ['id', 'token']

    def validate(self, data):
        try:
            usuario = data.get('usuario')
            if TokenRecuperacion.objects.filter(usuario=usuario, is_active=True).exists():
                raise serializers.ValidationError(
                    "Ya existe un token de recuperación activo para este usuario."
                )
            return data
        except Exception as e:
            logger.error(f"Error en validación de TokenRecuperacion: {str(e)}")
            raise serializers.ValidationError("Error al validar el token de recuperación")

class RegistroIntentoLoginSerializer(serializers.ModelSerializer):
    usuario = UsuarioInfoSerializer(read_only=True)

    class Meta:
        model = RegistroIntentoLogin
        fields = ['id', 'usuario', 'email_ingresado', 'exitoso', 'ip', 'user_agent', 'fecha_hora']
        read_only_fields = ['id', 'fecha_hora']

class SensorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Sensor
        fields = [
            'id', 'tipo_sensor', 'modelo', 'unidad_medida',
            'fecha_instalacion', 'fecha_ultima_calibracion',
            'estado', 'estacion', 'rango_minimo', 'rango_maximo',
            'created_at', 'updated_at', 'is_active'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_estado(self, value):
        estados_validos = ['activo', 'inactivo', 'mantenimiento', 'calibracion']
        if value not in estados_validos:
            raise serializers.ValidationError(
                f"El estado debe ser uno de los siguientes: {', '.join(estados_validos)}"
            )
        return value

    def validate_estacion(self, value):
        if not value:
            raise serializers.ValidationError("La estación es requerida")
        return value

    def validate_fecha_instalacion(self, value):
        if not value:
            raise serializers.ValidationError("La fecha de instalación es requerida")
        return value

    def validate(self, data):
        if data.get('rango_minimo') is not None and data.get('rango_maximo') is not None:
            if data['rango_minimo'] >= data['rango_maximo']:
                raise serializers.ValidationError(
                    "El rango mínimo debe ser menor que el rango máximo"
                )
        return data

class ZonaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Zona
        fields = [
            'id', 'nombre_zona', 'descripcion',
            'created_at', 'updated_at', 'is_active'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_nombre_zona(self, value):
        if not value:
            raise serializers.ValidationError("El nombre de la zona es requerido")
        if Zona.objects.filter(nombre_zona=value).exists():
            raise serializers.ValidationError("Ya existe una zona con este nombre")
        return value

class EstacionSerializer(serializers.ModelSerializer):
    zona_nombre = serializers.CharField(source='zona.nombre_zona', read_only=True)

    class Meta:
        model = Estacion
        fields = [
            'id', 'nombre_estacion', 'ubicacion',
            'zona', 'zona_nombre', 'created_at',
            'updated_at', 'is_active'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'zona_nombre']

    def validate_nombre_estacion(self, value):
        if not value:
            raise serializers.ValidationError("El nombre de la estación es requerido")
        if Estacion.objects.filter(nombre_estacion=value).exists():
            raise serializers.ValidationError("Ya existe una estación con este nombre")
        return value

    def validate_zona(self, value):
        if not value:
            raise serializers.ValidationError("La zona es requerida")
        return value

class LecturaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Lectura
        fields = [
            'id', 'sensor', 'valor', 'fecha_hora',
            'calidad_dato', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_valor(self, value):
        if value < -1000 or value > 1000:
            raise serializers.ValidationError(
                "El valor debe estar entre -1000 y 1000"
            )
        return value

    def validate_calidad_dato(self, value):
        calidades_validas = ['bueno', 'dudoso', 'malo']
        if value not in calidades_validas:
            raise serializers.ValidationError(
                f"La calidad del dato debe ser una de las siguientes: {', '.join(calidades_validas)}"
            )
        return value

    def validate_sensor(self, value):
        if not value:
            raise serializers.ValidationError("El sensor es requerido")
        return value

    def validate_fecha_hora(self, value):
        if not value:
            raise serializers.ValidationError("La fecha y hora son requeridas")
        return value

class AlertaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alerta
        fields = [
            'id', 'sensor', 'tipo_alerta', 'descripcion',
            'nivel_alerta', 'fecha_hora', 'atendida',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_tipo_alerta(self, value):
        tipos_validos = ['error', 'advertencia', 'info']
        if value not in tipos_validos:
            raise serializers.ValidationError(
                f"El tipo de alerta debe ser uno de los siguientes: {', '.join(tipos_validos)}"
            )
        return value

    def validate_nivel_alerta(self, value):
        niveles_validos = ['bajo', 'medio', 'alto']
        if value not in niveles_validos:
            raise serializers.ValidationError(
                f"El nivel de alerta debe ser uno de los siguientes: {', '.join(niveles_validos)}"
            )
        return value

    def validate_sensor(self, value):
        if not value:
            raise serializers.ValidationError("El sensor es requerido")
        return value

    def validate_fecha_hora(self, value):
        if not value:
            raise serializers.ValidationError("La fecha y hora son requeridas")
        return value 