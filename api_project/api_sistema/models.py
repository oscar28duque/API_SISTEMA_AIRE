from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
import uuid

class UsuarioManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('El email es requerido')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(username, email, password, **extra_fields)

#modelo de usuario
class Usuario(AbstractUser):
    ESTADO_CUENTA_CHOICES = [
        ('activo', 'Activo'),
        ('inactivo', 'Inactivo'),
        ('bloqueado', 'Bloqueado'),
    ]
    
    email = models.EmailField(unique=True)
    estado_cuenta = models.CharField(
        max_length=10,
        choices=ESTADO_CUENTA_CHOICES,
        default='activo'
    )
    fecha_registro = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(null=True, blank=True)
    date_joined = models.DateTimeField(default=timezone.now)
    
    objects = UsuarioManager()
    
    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']
    
    class Meta:
        verbose_name = 'Usuario'
        verbose_name_plural = 'Usuarios'
        ordering = ['-date_joined']
    
    def __str__(self):
        return f"{self.username} ({self.email})"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        return self.first_name

#modelo de rol
class Rol(models.Model):
    nombre_rol = models.CharField(max_length=50, unique=True)
    descripcion = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Rol'
        verbose_name_plural = 'Roles'

    def __str__(self):
        return self.nombre_rol

#modelo de usuario rol
class UsuarioRol(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='usuario_roles')
    rol = models.ForeignKey(Rol, on_delete=models.CASCADE, related_name='usuario_roles')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Usuario Rol'
        verbose_name_plural = 'Usuarios Roles'
        unique_together = ('usuario', 'rol')

    def __str__(self):
        return f"{self.usuario.username} - {self.rol.nombre_rol}"

#modelo de token de recuperacion
class TokenRecuperacion(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='tokens_recuperacion')
    token = models.CharField(max_length=100, unique=True)
    fecha_generacion = models.DateTimeField(auto_now_add=True)
    fecha_expiracion = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Token de Recuperación'
        verbose_name_plural = 'Tokens de Recuperación'

    def __str__(self):
        return f"Token para {self.usuario.username}"

#modelo de registro de intento de login 
class RegistroIntentoLogin(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, null=True, blank=True, related_name='intentos_login')
    email_ingresado = models.EmailField()
    exitoso = models.BooleanField(default=False)
    ip = models.GenericIPAddressField()
    user_agent = models.TextField()
    fecha_hora = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'Registro de Intento de Login'
        verbose_name_plural = 'Registros de Intentos de Login'

    def __str__(self):
        return f"Intento de {self.email_ingresado} - {'Exitoso' if self.exitoso else 'Fallido'}"

#modelo de zona
class Zona(models.Model):
    nombre_zona = models.CharField(max_length=100, unique=True)
    descripcion = models.TextField()
    latitud = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitud = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Zona'
        verbose_name_plural = 'Zonas'

    def __str__(self):
        return self.nombre_zona

#modelo de estacion
class Estacion(models.Model):
    nombre_estacion = models.CharField(max_length=100, unique=True)
    ubicacion = models.TextField()
    latitud = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    longitud = models.DecimalField(max_digits=9, decimal_places=6, null=True, blank=True)
    zona = models.ForeignKey(Zona, on_delete=models.CASCADE, related_name='estaciones')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Estación'
        verbose_name_plural = 'Estaciones'

    def __str__(self):
        return self.nombre_estacion

#modelo de sensor
class Sensor(models.Model):
    ESTADOS_SENSOR = [
        ('activo', 'Activo'),
        ('inactivo', 'Inactivo'),
        ('mantenimiento', 'Mantenimiento'),
        ('calibracion', 'Calibración')
    ]

    tipo_sensor = models.CharField(max_length=100)
    modelo = models.CharField(max_length=100)
    unidad_medida = models.CharField(max_length=50)
    fecha_instalacion = models.DateField()
    fecha_ultima_calibracion = models.DateField(null=True, blank=True)
    estado = models.CharField(max_length=20, choices=ESTADOS_SENSOR)
    estacion = models.ForeignKey(Estacion, on_delete=models.CASCADE, related_name='sensores')
    rango_minimo = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    rango_maximo = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Sensor'
        verbose_name_plural = 'Sensores'

    def __str__(self):
        return f"{self.tipo_sensor} - {self.modelo}"

#modelo de lectura      
class Lectura(models.Model):
    sensor = models.ForeignKey(Sensor, on_delete=models.CASCADE, related_name='lecturas')
    valor = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        validators=[
            MinValueValidator(-1000),
            MaxValueValidator(1000)
        ]
    )
    fecha_hora = models.DateTimeField()
    calidad_dato = models.CharField(
        max_length=20,
        choices=[
            ('bueno', 'Bueno'),
            ('dudoso', 'Dudoso'),
            ('malo', 'Malo')
        ],
        default='bueno'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Lectura'
        verbose_name_plural = 'Lecturas'
        indexes = [
            models.Index(fields=['fecha_hora']),
            models.Index(fields=['sensor', 'fecha_hora']),
        ]

#modelo de alerta
class Alerta(models.Model):
    NIVELES_ALERTA = [
        ('bajo', 'Bajo'),
        ('medio', 'Medio'),
        ('alto', 'Alto'),
        ('critico', 'Crítico')
    ]

    sensor = models.ForeignKey(Sensor, on_delete=models.CASCADE, related_name='alertas')
    tipo_alerta = models.CharField(max_length=100)
    descripcion = models.TextField()
    nivel_alerta = models.CharField(max_length=10, choices=NIVELES_ALERTA)
    fecha_hora = models.DateTimeField(auto_now_add=True)
    atendida = models.BooleanField(default=False)
    atendida_por = models.ForeignKey(Usuario, on_delete=models.SET_NULL, null=True, blank=True, related_name='alertas_atendidas')
    fecha_atencion = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Alerta'
        verbose_name_plural = 'Alertas'
        indexes = [
            models.Index(fields=['fecha_hora']),
            models.Index(fields=['sensor', 'fecha_hora']),
        ]

#modelo de reporte
class Reporte(models.Model):
    titulo = models.CharField(max_length=200)
    descripcion = models.TextField()
    fecha_creacion = models.DateTimeField(auto_now_add=True)
    generado_por = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='reportes_generados')
    periodo_inicio = models.DateTimeField()
    periodo_fin = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = 'Reporte'
        verbose_name_plural = 'Reportes'

#modelo de detalle de reporte   
class DetalleReporte(models.Model):
    reporte = models.ForeignKey(Reporte, on_delete=models.CASCADE, related_name='detalles')
    contenido = models.TextField()
    tipo_contenido = models.CharField(
        max_length=50,
        choices=[
            ('texto', 'Texto'),
            ('grafico', 'Gráfico'),
            ('tabla', 'Tabla'),
            ('resumen', 'Resumen')
        ]
    )
    orden = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Detalle de Reporte'
        verbose_name_plural = 'Detalles de Reporte'
        ordering = ['orden']

#modelo de configuracion de dashboard
class ConfiguracionDashboard(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='configuraciones_dashboard')
    tipo_visualizacion = models.CharField(max_length=50)
    parametros = models.JSONField()
    fecha_configuracion = models.DateTimeField(auto_now_add=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = 'Configuración de Dashboard'
        verbose_name_plural = 'Configuraciones de Dashboard'

#modelo de log de actividad
class LogActividad(models.Model):
    usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE, related_name='logs_actividad')
    modulo = models.CharField(max_length=100)
    accion = models.CharField(max_length=100)
    descripcion_evento = models.TextField()
    fecha_hora = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = 'Log de Actividad'
        verbose_name_plural = 'Logs de Actividad'
        indexes = [
            models.Index(fields=['fecha_hora']),
            models.Index(fields=['usuario', 'fecha_hora']),
        ]
