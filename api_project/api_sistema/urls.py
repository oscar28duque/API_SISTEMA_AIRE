from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from . import views

urlpatterns = [
    # Autenticación
    path('auth/registro/', views.registro_usuario, name='registro_usuario'),
    path('auth/login/', views.login_usuario, name='login_usuario'),
    path('auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/usuario-actual/', views.usuario_actual, name='usuario_actual'),
    
    # Recuperación de contraseña
    path('auth/solicitar-recuperacion/', views.solicitar_recuperacion_password, name='solicitar_recuperacion'),
    path('auth/verificar-token/', views.verificar_token_recuperacion, name='verificar_token'),
    path('auth/cambiar-password/', views.cambiar_password, name='cambiar_password'),
    
    # CRUD Usuarios
    path('usuarios/', views.usuarios, name='usuarios'),
    path('usuarios/<int:pk>/', views.usuario_detalle, name='usuario_detalle'),
    
    # CRUD Roles
    path('roles/', views.roles, name='roles'),
    path('roles/<int:pk>/', views.rol_detalle, name='rol_detalle'),
    
    # CRUD UsuarioRol
    path('usuarios-roles/', views.usuarios_roles, name='usuarios_roles'),
    path('usuarios-roles/<int:pk>/', views.usuario_rol_detalle, name='usuario_rol_detalle'),
    
    # CRUD TokenRecuperacion
    path('tokens-recuperacion/', views.tokens_recuperacion, name='tokens_recuperacion'),
    path('tokens-recuperacion/<int:pk>/', views.token_recuperacion_detalle, name='token_recuperacion_detalle'),
    
    # CRUD RegistroIntentoLogin
    path('intentos-login/', views.intentos_login, name='intentos_login'),
    path('intentos-login/<int:pk>/', views.intento_login_detalle, name='intento_login_detalle'),
] 