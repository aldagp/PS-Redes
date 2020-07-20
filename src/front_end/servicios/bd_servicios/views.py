from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes, authentication_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.throttling import UserRateThrottle
import json
from bd_servicios import back_end
import psutil
# Create your views here.
@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
@throttle_classes([UserRateThrottle])

def porcentajes(request):
	if request.method == 'GET':
		disk_usage = psutil.disk_usage("/")
		memory = psutil.virtual_memory()
		CPU = psutil.cpu_percent(interval=1)
		disco_usado = format(disk_usage.percent)
		memoria_usada = format(memory.percent)
		cpu_usado = format(CPU)
		datos_raw = '[{"Disco": "Porcentaje disco %s "}, {"Memoria": "Porcentaje Memoria RAM %s"}, {"CPU": "Porcentaje CPU %s"}]' % (disco_usado, memoria_usada, cpu_usado)
		datos = json.loads(datos_raw)
		return Response(datos)



#		usuario = request.META.get('CLIENTE_SERVICIOS_USR','') #Aqui invento el diccionario
#		password = request.META.get('CLIENTE_SERVICIOS_PWD','')

#Aqui van los datos que arroja el sistema
#		datos_raw = '[{"nombre": "Aldair Garrido"},{"nombre": "Carlos Uscaga"}]'
#		datos = json.loads(datos_raw)
#		datos= back_end.regresar_servicios(CLIENTE_SERVICIOS_USR, CLIENTE_SERVICIOS_PWD)
#		if not datos:
#			Response({'Error':'No se pudieron recuperar los datos'})
#		return Response(datos)