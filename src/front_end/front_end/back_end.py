from bd import models
import datetime
import front_end.settings as settings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from front_end import settings
import requests
from front_end import excepciones
import json
from secrets import choice 
import mysql.connector
import crypt

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def dejar_pasar_peticion_login(request):
    ip = get_client_ip(request)
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    try:
        registro = models.IPs.objects.get(ip=ip)
    except: # la ip nunca ha hecho peticiones
        nuevoRegistroIP = models.IPs(ip=ip, ultima_peticion=timestamp, intentos=1)
        nuevoRegistroIP.save()
        return True
    diferencia = (timestamp - registro.ultima_peticion).seconds
    if diferencia > settings.VENTANA_TIEMPO_INTENTOS_LOGIN:
        registro.ultima_peticion = timestamp
        registro.intentos=1
        registro.save()
        return True
    elif settings.INTENTOS_LOGIN > registro.intentos:
        registro.ultima_peticion = timestamp
        registro.intentos = registro.intentos+1
        registro.save()
        return True
    else:
        registro.ultima_peticion = timestamp
        registro.intentos = registro.intentos+1
        registro.save()
        return False
def cifrar(mensaje, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    cifrador = aesCipher.encryptor()    
    cifrado = cifrador.update(mensaje)
    cifrador.finalize()
    return cifrado

def descifrar(cifrado, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    descifrador = aesCipher.decryptor()
    plano = descifrador.update(cifrado)
    descifrador.finalize()
    return plano

def generar_llave():
    llave_aes = os.urandom(16)
    iv = os.urandom(16)
    return llave_aes, iv

def cifrar_credenciales(usuario, password, llave_aes_usr, iv_usr, llave_aes_pwd, iv_pwd):

    usuario_cifrado = cifrar(usuario.encode('utf-8'), llave_aes_usr, iv_usr)
    password_cifrado = cifrar(password.encode('utf-8'), llave_aes_pwd, iv_pwd)
    return usuario_cifrado, password_cifrado

def convertir_dato_base64(dato):
    return base64.b64encode(dato).decode('utf-8')

def generaHash(password):
    #print(password)
    salt = base64.b64encode(os.urandom(10)).decode('utf-8')
    hasheado = crypt.crypt(password, '$6$' + salt)
    return hasheado

#def convertir_dato_base64(dato):
#    return base64.b64encode(dato).decode('utf-8')

#def convertir_base64_dato(dato_b64):
#    return base64.b64decode(dato_b64)

def mandarMensaje(chatID,token):
    BOT_TOKEN = '1237141449:AAFjlpP7zV14jsIdHqrW0EC6a1hbp1jKqo4'
    send_text = 'https://api.telegram.org/bot%s/sendMessage?chat_id=%s&parse_mode=Markdown&text=%s' % (BOT_TOKEN, chatID, token)
    response = requests.get(send_text)
    return response.json()


def generaToken():
    caracteres = '\{}!=?¿¡!|/()@=abcdefghijklmnopqrstuvwxyz1234567890'
    longitud = 12
    token = ''.join(choice(caracteres) for caracter in range(longitud))
    return token


def registraToken(token, usuario, horaCreacionToken, tabla):
    mydb = mysql.connector.connect(
        host=settings.host,
        user=settings.user,
        password=settings.password,
        database=settings.database
        )
    mycursor = mydb.cursor()

    if tabla == 'adminServ':
        sql = "UPDATE bd_adminservidores SET token= %s, horaToken=%s WHERE usuario = %s"
        val = (token, horaCreacionToken, usuario)
        mycursor.execute(sql, val)
        mydb.commit()
    if tabla == 'adminGlobal':
        sql = "UPDATE bd_adminglobal SET token= %s, horaToken=%s WHERE usuario = %s"
        val = (token, horaCreacionToken, usuario)
        mycursor.execute(sql, val)
        mydb.commit()


def borrarToken(usuario, tabla):
    mydb = mysql.connector.connect(
        host=settings.host,
        user=settings.user,
        password=settings.password,
        database=settings.database
        )
    mycursor = mydb.cursor()
    if tabla == 'adminServ':
        sql = "UPDATE bd_adminglobal SET token= %s WHERE usuario = %s"
        val = ('NULL', usuario)
        mycursor.execute(sql, val)
        mydb.commit()

    if tabla == 'adminGlobal':
        sql = "UPDATE bd_adminglobal SET token= %s WHERE usuario = %s"
        val = ('NULL', usuario)
        mycursor.execute(sql, val)
        mydb.commit()

def regresar_token_session():
    settings.ADMINSERV_ACTIVO
    auxToken = ''
    datosAdminServ = models.adminServidores.objects.all()
    datosServ = models.servidores.objects.all()

    for datos in datosServ:
        if datos.adminServ_id == settings.ADMINSERV_ACTIVO:
            url_token = datos.direccionIp + '/autenticacion/'  # aqui se tiene que recuperar la IP registrada en el servidor
            data = {'username': datos.usuarioAPI,
                    'password': datos.passwordAPI}  # pass y usr de la BD
            respuesta = requests.post(url_token, data=data)
            if respuesta.status_code != 200:
                raise excepciones.TokenException('no se pudo recuperar el token %s' % respuesta.status_code)
            else:
                diccionario = json.loads(respuesta.text)
                print("token", diccionario)
                return diccionario['token']#cambiar este pedo xd


def regresar_monitoreo(request, token):
    settings.ADMINSERV_ACTIVO
    datosAdminServ = models.adminServidores.objects.all()
    datosServ = models.servidores.objects.all()

    for datos in datosServ:
        if datos.adminServ_id == settings.ADMINSERV_ACTIVO:
            url_monitoreo = datos.direccionIp + '/porcentajes/'  # aqui se tiene que recuperar la IP registrada en el servidor en lugar de ser estatico
            headers = {'Authorization': 'Token %s' % token}
            respuesta = requests.get(url_monitoreo, headers=headers)
            if respuesta.status_code != 200:
                raise excepciones.monitoreoException('Error monitoreo %s' % respuesta.status_code)
            else:
                monitoreo = json.loads(respuesta.text)
                return monitoreo

#def regresar_token_sesion(usuario, password):
#        url_token = settings.URL_SERVICIOS + '/autenticacion/'
#        data = {'username': settings.CLIENTE_SERVICIOS_USR, 'password': settings.CLIENTE_SERVICIOS_PWD}
#        respuesta = requests.post(url_token, data=data)
#        if respuesta.status_code != 200:
#            raise TokenException('No se pudo recuperar el token: %s' % respuesta.status_code)
#        else:
#            diccionario = json.loads(respuesta.text)
#            return diccionario['token']

#def regresar_servicios(request, token):
#    url_monitor = settings.URL_SERVICIOS + '/cursos/'
#    headers = {'Authorization':'Token %s' %token}
#    respuesta = requests.post(url_monitor, headers=headers)
#    if respuesta.status_code != 200:
#        raise excepciones.MonitorException('Hubo en error al querer recuperar el monitoreo: %s' % respuesta.status_code)
#    else:
#        cursos = json.loads(respuesta.text)
#    return cursos

