from django.db import migrations, models
import secrets

def cleanup_tokens(apps, schema_editor):
    TokenRecuperacion = apps.get_model('api_sistema', 'TokenRecuperacion')
    for token in TokenRecuperacion.objects.all():
        if not token.token:
            token.token = secrets.token_urlsafe(32)
            token.save()

class Migration(migrations.Migration):

    dependencies = [
        ('api_sistema', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(cleanup_tokens),
        migrations.RemoveField(
            model_name='estacion',
            name='latitud',
        ),
        migrations.RemoveField(
            model_name='estacion',
            name='longitud',
        ),
        migrations.RemoveField(
            model_name='zona',
            name='latitud',
        ),
        migrations.RemoveField(
            model_name='zona',
            name='longitud',
        ),
        migrations.AlterField(
            model_name='tokenrecuperacion',
            name='token',
            field=models.CharField(default=secrets.token_urlsafe, max_length=100, unique=True),
        ),
    ] 