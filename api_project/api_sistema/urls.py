from django.urls import path
from . import views

urlpatterns = [
    # Autenticación
    path('registro/', views.registro_usuario, name='registro_usuario'),
    path('login/', views.login_usuario, name='login_usuario'),
    path('usuario/actual/', views.usuario_actual, name='usuario_actual'),
    
    # Gestión de Roles
    path('roles/', views.crear_rol, name='crear_rol'),
    path('usuarios/roles/', views.asignar_rol_usuario, name='asignar_rol_usuario'),
    
    # Recuperación de Contraseña
    path('recuperar-password/', views.solicitar_recuperacion_password, name='solicitar_recuperacion_password'),
    path('reset-password/', views.resetear_password, name='resetear_password'),
    
    # Registro de Intentos de Login
    path('login/intentos/', views.ver_intentos_login, name='ver_intentos_login'),
] 