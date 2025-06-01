from django.test import TestCase
from django.utils import timezone
from django.core.exceptions import ValidationError
from decimal import Decimal
from .models import (
    Usuario, Rol, UsuarioRol, Zona, Estacion, 
    Sensor, Lectura, Alerta, Reporte, DetalleReporte,
    ConfiguracionDashboard, LogActividad
)

class UsuarioModelTest(TestCase):
    def setUp(self):
        self.usuario_data = {
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpass123',
            'first_name': 'Test',
            'last_name': 'User'
        }
        self.usuario = Usuario.objects.create_user(**self.usuario_data)

    def test_crear_usuario(self):
        self.assertEqual(self.usuario.username, 'testuser')
        self.assertEqual(self.usuario.email, 'test@example.com')
        self.assertEqual(self.usuario.estado_cuenta, 'activo')
        self.assertTrue(self.usuario.is_active)

    def test_get_full_name(self):
        self.assertEqual(self.usuario.get_full_name(), 'Test User')

    def test_get_short_name(self):
        self.assertEqual(self.usuario.get_short_name(), 'Test')

class RolModelTest(TestCase):
    def setUp(self):
        self.rol = Rol.objects.create(
            nombre_rol='Administrador',
            descripcion='Rol de administrador del sistema'
        )

    def test_crear_rol(self):
        self.assertEqual(self.rol.nombre_rol, 'Administrador')
        self.assertEqual(self.rol.descripcion, 'Rol de administrador del sistema')
        self.assertTrue(self.rol.is_active)

class ZonaModelTest(TestCase):
    def setUp(self):
        self.zona = Zona.objects.create(
            nombre_zona='Zona Norte',
            descripcion='Zona norte de la ciudad',
            latitud=Decimal('19.4326'),
            longitud=Decimal('-99.1332')
        )

    def test_crear_zona(self):
        self.assertEqual(self.zona.nombre_zona, 'Zona Norte')
        self.assertEqual(self.zona.descripcion, 'Zona norte de la ciudad')
        self.assertEqual(self.zona.latitud, Decimal('19.4326'))
        self.assertEqual(self.zona.longitud, Decimal('-99.1332'))
        self.assertTrue(self.zona.is_active)

class EstacionModelTest(TestCase):
    def setUp(self):
        self.zona = Zona.objects.create(
            nombre_zona='Zona Norte',
            descripcion='Zona norte de la ciudad'
        )
        self.estacion = Estacion.objects.create(
            nombre_estacion='Estación Central',
            ubicacion='Centro de la ciudad',
            zona=self.zona,
            latitud=Decimal('19.4326'),
            longitud=Decimal('-99.1332')
        )

    def test_crear_estacion(self):
        self.assertEqual(self.estacion.nombre_estacion, 'Estación Central')
        self.assertEqual(self.estacion.ubicacion, 'Centro de la ciudad')
        self.assertEqual(self.estacion.zona, self.zona)
        self.assertEqual(self.estacion.latitud, Decimal('19.4326'))
        self.assertEqual(self.estacion.longitud, Decimal('-99.1332'))
        self.assertTrue(self.estacion.is_active)

class SensorModelTest(TestCase):
    def setUp(self):
        self.zona = Zona.objects.create(
            nombre_zona='Zona Norte',
            descripcion='Zona norte de la ciudad'
        )
        self.estacion = Estacion.objects.create(
            nombre_estacion='Estación Central',
            ubicacion='Centro de la ciudad',
            zona=self.zona
        )
        self.sensor = Sensor.objects.create(
            tipo_sensor='Temperatura',
            modelo='TEMP-001',
            unidad_medida='°C',
            fecha_instalacion=timezone.now().date(),
            estado='activo',
            estacion=self.estacion,
            rango_minimo=Decimal('-10.00'),
            rango_maximo=Decimal('50.00')
        )

    def test_crear_sensor(self):
        self.assertEqual(self.sensor.tipo_sensor, 'Temperatura')
        self.assertEqual(self.sensor.modelo, 'TEMP-001')
        self.assertEqual(self.sensor.unidad_medida, '°C')
        self.assertEqual(self.sensor.estado, 'activo')
        self.assertEqual(self.sensor.rango_minimo, Decimal('-10.00'))
        self.assertEqual(self.sensor.rango_maximo, Decimal('50.00'))
        self.assertTrue(self.sensor.is_active)

class LecturaModelTest(TestCase):
    def setUp(self):
        self.zona = Zona.objects.create(
            nombre_zona='Zona Norte',
            descripcion='Zona norte de la ciudad'
        )
        self.estacion = Estacion.objects.create(
            nombre_estacion='Estación Central',
            ubicacion='Centro de la ciudad',
            zona=self.zona
        )
        self.sensor = Sensor.objects.create(
            tipo_sensor='Temperatura',
            modelo='TEMP-001',
            unidad_medida='°C',
            fecha_instalacion=timezone.now().date(),
            estado='activo',
            estacion=self.estacion
        )
        self.lectura = Lectura.objects.create(
            sensor=self.sensor,
            valor=Decimal('25.50'),
            fecha_hora=timezone.now(),
            calidad_dato='bueno'
        )

    def test_crear_lectura(self):
        self.assertEqual(self.lectura.sensor, self.sensor)
        self.assertEqual(self.lectura.valor, Decimal('25.50'))
        self.assertEqual(self.lectura.calidad_dato, 'bueno')

    def test_lectura_valor_limites(self):
        with self.assertRaises(ValidationError):
            Lectura.objects.create(
                sensor=self.sensor,
                valor=Decimal('1500.00'),  # Valor fuera de rango
                fecha_hora=timezone.now(),
                calidad_dato='bueno'
            )

class AlertaModelTest(TestCase):
    def setUp(self):
        self.zona = Zona.objects.create(
            nombre_zona='Zona Norte',
            descripcion='Zona norte de la ciudad'
        )
        self.estacion = Estacion.objects.create(
            nombre_estacion='Estación Central',
            ubicacion='Centro de la ciudad',
            zona=self.zona
        )
        self.sensor = Sensor.objects.create(
            tipo_sensor='Temperatura',
            modelo='TEMP-001',
            unidad_medida='°C',
            fecha_instalacion=timezone.now().date(),
            estado='activo',
            estacion=self.estacion
        )
        self.alerta = Alerta.objects.create(
            sensor=self.sensor,
            tipo_alerta='Temperatura Alta',
            descripcion='La temperatura ha superado el umbral máximo',
            nivel_alerta='alto'
        )

    def test_crear_alerta(self):
        self.assertEqual(self.alerta.sensor, self.sensor)
        self.assertEqual(self.alerta.tipo_alerta, 'Temperatura Alta')
        self.assertEqual(self.alerta.nivel_alerta, 'alto')
        self.assertFalse(self.alerta.atendida)
        self.assertIsNone(self.alerta.atendida_por)
        self.assertIsNone(self.alerta.fecha_atencion)

class ReporteModelTest(TestCase):
    def setUp(self):
        self.usuario = Usuario.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.reporte = Reporte.objects.create(
            titulo='Reporte Mensual',
            descripcion='Reporte de actividades del mes',
            generado_por=self.usuario,
            periodo_inicio=timezone.now(),
            periodo_fin=timezone.now()
        )

    def test_crear_reporte(self):
        self.assertEqual(self.reporte.titulo, 'Reporte Mensual')
        self.assertEqual(self.reporte.descripcion, 'Reporte de actividades del mes')
        self.assertEqual(self.reporte.generado_por, self.usuario)
        self.assertTrue(self.reporte.is_active)

class DetalleReporteModelTest(TestCase):
    def setUp(self):
        self.usuario = Usuario.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.reporte = Reporte.objects.create(
            titulo='Reporte Mensual',
            descripcion='Reporte de actividades del mes',
            generado_por=self.usuario,
            periodo_inicio=timezone.now(),
            periodo_fin=timezone.now()
        )
        self.detalle = DetalleReporte.objects.create(
            reporte=self.reporte,
            contenido='Contenido del detalle',
            tipo_contenido='texto',
            orden=1
        )

    def test_crear_detalle_reporte(self):
        self.assertEqual(self.detalle.reporte, self.reporte)
        self.assertEqual(self.detalle.contenido, 'Contenido del detalle')
        self.assertEqual(self.detalle.tipo_contenido, 'texto')
        self.assertEqual(self.detalle.orden, 1)
