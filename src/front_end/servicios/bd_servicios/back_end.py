#import subprocess
#from servicios import settings
#import os
#import json


#def regresar_servicios(CLIENTE_SERVICIOS_USR, CLIENTE_SERVICIOS_PWD):
#	os.environ.putenv('CLIENTE_SERVICIOS_USR', CLIENTE_SERVICIOS_USR)
#	os.environ.putenv('CLIENTE_SERVICIOS_PWD', CLIENTE_SERVICIOS_PWD)
#	comando = f'python3 {settings.PATH_BACK_END}/Disco.py'
#	salida = subprocess.Popen(comando, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
#	stdout, stderr = salida.communicate()
#	if not stderr:
#		raise None
#	return json.loads(stdout)