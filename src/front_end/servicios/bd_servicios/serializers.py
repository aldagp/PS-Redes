from rest_framework import serializers 
from bd_servicios import models

class monitoroSerializer(serializers.Serializer):
	porcentaje_cpu = serializers.CharField(max_length=10)
	porcentaje_memoria = serializers.CharField(max_length=10)
	porcentaje_disco = serializers.CharField(max_length=10)

#	servidor = serializers.CharField(max_length=100)
#	nombre = serializers.CharField(max_length=100)
