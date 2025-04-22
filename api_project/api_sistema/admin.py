from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Usuario, Rol, UsuarioRol, TokenRecuperacion, RegistroIntentoLogin

class UsuarioAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'estado_cuenta', 'is_active', 'date_joined')
    list_filter = ('estado_cuenta', 'is_active', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    filter_horizontal = ('groups', 'user_permissions',)

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Información Personal', {'fields': ('first_name', 'last_name', 'email')}),
        ('Estado', {'fields': ('estado_cuenta', 'is_active', 'is_staff', 'is_superuser')}),
        ('Permisos', {'fields': ('groups', 'user_permissions')}),
        ('Fechas Importantes', {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2', 'first_name', 'last_name', 'estado_cuenta'),
        }),
    )

class RolAdmin(admin.ModelAdmin):
    list_display = ('nombre_rol', 'descripcion', 'is_active')
    search_fields = ('nombre_rol',)

class UsuarioRolAdmin(admin.ModelAdmin):
    list_display = ('usuario', 'rol')
    list_filter = ('rol',)
    search_fields = ('usuario__username', 'usuario__email')

class TokenRecuperacionAdmin(admin.ModelAdmin):
    list_display = ('usuario', 'fecha_generacion', 'fecha_expiracion', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('usuario__username', 'usuario__email')

class RegistroIntentoLoginAdmin(admin.ModelAdmin):
    list_display = ('usuario', 'email_ingresado', 'fecha_hora', 'exitoso', 'ip')
    list_filter = ('exitoso', 'fecha_hora')
    search_fields = ('usuario__username', 'email_ingresado', 'ip')

admin.site.register(Usuario, UsuarioAdmin)
admin.site.register(Rol, RolAdmin)
admin.site.register(UsuarioRol, UsuarioRolAdmin)
admin.site.register(TokenRecuperacion, TokenRecuperacionAdmin)
admin.site.register(RegistroIntentoLogin, RegistroIntentoLoginAdmin)
