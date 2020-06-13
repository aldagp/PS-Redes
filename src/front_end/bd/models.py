from django.db import models

# Create your models here.
class IPs(models.Model):
	ip = models.GenericIPAddressField(null=False, blank=False, unique=True)
	ultima_peticion = models.DateTimeField(null=False, blank=False)
	intentos = models.IntegerField(null=False, blank=False, default=0)

class adminGlobal(models.Model):
	usuario=models.CharField(max_length=40)
	password=models.CharField(max_length=20)

class adminServidores(models.Model):
	usuario=models.CharField(max_length=40)
	password=models.CharField(max_length=20)

