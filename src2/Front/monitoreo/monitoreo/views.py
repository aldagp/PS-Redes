from subprocess import Popen
from datetime import datetime, timezone
from django.shortcuts import render, redirect
import json
import base64
import os
import crypt
import re
import monitoreo.validaIp as validaIp
from monitoreoAppl import models
from secrets import choice
from monitoreoAppl import decoradores
import mysql.connector
import requests
from monitoreo import settings
from monitoreoAppl import excepciones
from monitoreoAppl.excepciones import TokenException

from monitoreoAppl.models import adminServidores
from monitoreoAppl.models import servidores
from monitoreoAppl.forms import adminServerForm, servidoresForm


import logging
logging.basicConfig(filename='Bitacora.log', filemode='a', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)


def login(request):
    t = 'login.html'
    if request.method == 'GET':
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        return render(request, t)
    elif request.method == 'POST':
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        if validaIp.dejar_pasar_peticion_login(request):
            usuario = request.POST.get('usuario').strip()
            password = request.POST.get('password').strip()
            datosAdminGlobal = models.adminGlobal.objects.all()
            datosAdminServ = models.adminServidores.objects.all()
            for datos in datosAdminGlobal:
                if datos.usuario == usuario:
                    passwordBase = datos.password
                    partes = passwordBase.split('$')
                    header = '$' + partes[1] + '$' + partes[2]
                    passwordTemplate = crypt.crypt(password, header)
                    if passwordBase == passwordTemplate:
                        request.session['prelogueado'] = True
                        chatID = datos.chatID
                        token = generaToken()
                        horaCreacionToken = datetime.now()
                        horaCreacionToken.replace(tzinfo=None)
                        mandarMensaje(chatID, token)
                        registraToken(token, datos.usuario, horaCreacionToken, 'adminGlobal')
                        return redirect('/token/')
                    
            for datos in datosAdminServ:
                if datos.usuario == usuario:
                    passwordBase = datos.password
                    partes = passwordBase.split('$')
                    header = '$' + partes[1] + '$' + partes[2]
                    passwordTemplate = crypt.crypt(password, header)
                    if passwordBase == passwordTemplate:
                        request.session['prelogueado'] = True
                        chatID = datos.chatID
                        token = generaToken()
                        horaCreacionToken = datetime.now(timezone.utc)
                        mandarMensaje(chatID, token)
                        registraToken(token, datos.usuario, horaCreacionToken,'adminServ')
                        return redirect('/token/')
                    else:
                        return render(request, t, {'errores': 'Error en el credeciales'})
            return render(request, t, {'errores': 'Error en el credeciales'})
        else:
            return render(request, t, {'errores': 'Numero de intentos excedido espera un minuto'})
    return render(request, t)


@decoradores.prelogueado
def token(request):
    t = 'token.html'
    t2 = 'login.html'
    if request.method == 'GET' and not request.session.get('logueadoAdminGlobal', False):
        return render(request, t)
    elif request.method == 'GET':
        return redirect('/funcionesAdminiGlobal/')
    elif request.method == 'GET' and not request.session.get('logueadoAdminServ', False):
        return render(request, t)
    elif request.method == 'GET':
        return redirect('/funcionesAdminServ/')
    elif request.method == 'POST':
        if request.session.get('logueadoAdminGlobal', False):
            return redirect('/funcionesAdminGlobal/')
        if request.session.get('logueadoAdminServ', False):
            return redirect('/funcionesAdminServ/')
        token = request.POST.get('token').strip()
        datosAdminGlobal = models.adminGlobal.objects.all()
        datosAdminServ = models.adminServidores.objects.all()
        for datos in datosAdminGlobal:
            horaActual = datetime.now(timezone.utc)
            print("Hora actual",horaActual.tzinfo)
            tokenErroneo = datos.token
            if datos.token == token:
                tokenExpira = (horaActual - datos.horaToken).seconds
                if tokenExpira >= 300:
                    borrarToken(datos.usuario, 'adminGlobal')
                    return redirect('/logout/')
                borrarToken(datos.usuario, 'adminGlobal')
                request.session['logueadoAdminGlobal'] = True
                return redirect('/funcionesAdminGlobal/')
        for datos in datosAdminServ:
            horaActual = datetime.now(timezone.utc)
            tokenErroneo = datos.token
            if datos.token == token:
                tokenExpira = (horaActual - datos.horaToken).seconds
                if tokenExpira >= 300:
                    borrarToken(datos.usuario, 'adminServ')
                    return redirect('/logout/')

                borrarToken(datos.usuario, 'adminServ')
                settings.ADMINSERV_ACTIVO = datos.id
                request.session['logueadoAdminServ'] = True
                return redirect('/funcionesAdminServ/') 
    request.session['prelogueado'] = False
    return render(request, t2, {'errores':'Error en el token'})


@decoradores.logueadoAdminGlobal
def funcionesAdminGlobal(request):
   usuarios = adminServidores.objects.all()
   data = {
       'misUsuarios':usuarios
    }

   return render(request, 'funcionesAdminGlobal.html', data)


@decoradores.logueadoAdminGlobal
def registrarAdminServ(request):
    t = 'registrarAdminServ.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':#validar entradas de datos
        usuario = request.POST.get('usuario').strip()
        password = request.POST.get('password').strip()
        chatID = request.POST.get('chatID').strip()
        datosAdminServ = models.adminServidores.objects.all()
        for datos in datosAdminServ:
            if datos.usuario == usuario:
                return render(request, t, {'errores': 'El nombre de usuario ya esta en uso, ingresa otro'})
            if datos.chatID == chatID:
                return render(request, t, {'errores': 'El chatID ya esta en uso '})
        if ' ' in usuario:
            return render(request, t, {'errores': 'El usuario  no debe tener espacios en la cadena '})
        else:
            longitud =len(usuario)
            longmax = 10
            longmin = 8
            if longitud >= longmin and longitud <= longmax:
                Mayusculas = len([c for c in usuario if c.isupper()])
                if Mayusculas >=  1 :
                    numeros = len([c for c in usuario if c.isdigit()])
                    if numeros >= 1 :
                        if ' ' in password:
                            return render(request, t, {'errores': 'La password  no debe tener espacios en la cadena '})
                        else:
                            longitud =len(password)
                            if longitud >= longmin and longitud <= longmax:
                                Mayusculas = len([c for c in password if c.isupper()])
                                if Mayusculas >=  1 :
                                    numeros = len([c for c in password if c.isdigit()])
                                    if numeros >= 1 :
                                        longitud = len(chatID)
                                        if longitud >= longmin and longitud <= longmax:
                                            if chatID.isdigit():
                                                mydb = mysql.connector.connect(
                                                    host=settings.host,
                                                    user=settings.user,
                                                    passwd=settings.passwd,
                                                    database=settings.database
                                                )
                                                mycursor = mydb.cursor()
                                                sql = "INSERT INTO monitoreoAppl_adminservidores (usuario, password, token, horaToken, chatID ) VALUES (%s, %s, %s, %s, %s)"
                                                passwordAux = generaHash(password)
                                                val = (usuario, passwordAux, 'NULL', datetime.now(timezone.utc), chatID)
                                                mycursor.execute(sql, val)
                                                mydb.commit()
                                                return render(request, t, {'errores': 'Usuario registrado'})
                                            else:
                                                return render(request, t, {'errores': 'El chatID debe ser numerico'})
                                        else:
                                            return render(request, t, {'errores': 'El chatID debe tener un minimo de 8 caracteres y un maximo de 10'})
                                    else:
                                        return render(request, t, {'errores': 'La password tiene que tener minimo 1 numero '})
                                else:
                                    return render(request, t, {'errores': 'La password tiene que tener almenos una mayuscula'})
                            else:
                                return render(request, t, {'errores': 'La password tiene que tener una longitud minima de 8 y maxima de 10'})
                    else:
                        return render(request, t, {'errores': 'El usuario tiene que tener minimo 1 numero '})
                else:
                    return render(request, t, {'errores': 'El usuario tiene que tener una Mayuscula'})
            else:
                return render(request, t, {'errores': 'El usuario tiene que tener  una longitud minima de 8 y maxima de 10'})



def actualizarAdminServ(request, id):
    usuarios = adminServidores.objects.get(id=id)
    data = {
        'form':adminServerForm(instance=usuarios)
    }

    if request.method == 'POST':
        formulario = adminServerForm(data=request.POST, instance=usuarios)
        if formulario.is_valid():
            formulario.save()
            data['mensaje'] = "Modificado correctamente"
            data['form'] = formulario
        else:
            data['mensaje'] = "No se guardo"
    return render (request, 'actualizarAdminServ.html', data)

def actualizarServer(request,adminServ_id):
    misServidores = servidores.objects.get(adminServ_id=adminServ_id)
    data = {
        'form':servidoresForm(instance=misServidores)
    }

    if request.method == 'POST':
        formulario = servidoresForm(data=request.POST, instance=misServidores)
        if formulario.is_valid():
            formulario.save()
            data['mensaje'] = "Modificado correctamente"
            data['form'] = formulario
        else:
            data['mensaje'] = "No se guardo"
    return render (request, 'actualizarServ.html', data)

def eliminarServ(request,adminServ_id):
    misServidores = servidores.objects.get(adminServ_id=adminServ_id)
    misServidores.delete()

    return redirect(to="verServidor")

def eliminarAdminServ(request, id):
    usuarios = adminServidores.objects.get(id=id)
    usuarios.delete()

    return redirect(to="funcionesAdminGlobal")


@decoradores.logueadoAdminGlobal
def mostrarServer(request):
    Servidores = servidores.objects.all()
    data = {
        'servidores':Servidores

    }
    return render(request, 'verServidor.html', data)

@decoradores.logueadoAdminGlobal
def registrarServer(request):
    data = {
        'formServidor':servidoresForm()
    }
    if request.method == 'POST':
        formulario = servidoresForm(request.POST)
        if formulario.is_valid():
            formulario.save()
            data['mensaje'] = "Guardado correctamente"
        else:
            data['mensaje'] = "No se guardo"
        
    return render(request, 'registrarServer.html', data)


@decoradores.logueadoAdminGlobal
def asociarServ(request):
    t = 'asociarServ.html'
    if request.method == 'GET':
        return render(request, t)
    elif request.method == 'POST':
        adminServidoresID = request.POST.get('adminServidoresID').strip()
        nombre = request.POST.get('nombre').strip()
        direccionIp = request.POST.get('direccionIP').strip()
        usuarioAPI = request.POST.get('usuarioAPI').strip()
        passwordAPI = request.POST.get('passwordAPI').strip()


        mydb = mysql.connector.connect(
            host=settings.host,
            user=settings.user,
            passwd=settings.passwd,
            database=settings.database
        )
        mycursor = mydb.cursor()
        sql = "INSERT INTO monitoreoAppl_servidores (nombre, direccionIp, usuarioAPI, passwordAPI, adminServ_id) VALUES (%s, %s, %s, %s, %s)"
        val = (nombre, direccionIp, usuarioAPI, passwordAPI, adminServidoresID)
        mycursor.execute(sql, val)
        mydb.commit()
        return render(request, t, {'errores': 'Asociacion completada'})



def mandarMensaje(chatID,token):

    BOT_TOKEN = '1260934375:AAEwWKDVbOP8_UsTqon0mRQlgvi2_sL3RgU'
    send_text = 'https://api.telegram.org/bot%s/sendMessage?chat_id=%s&parse_mode=Markdown&text=%s' % (BOT_TOKEN, chatID, token)
    response = requests.get(send_text)
    return response.json()


def generaToken():
    caracteres = '[]\{}!=?¿¡!|/()@=abcdefghijklmnopqrstuvwxyz1234567890'
    longitud = 12
    token = ''.join(choice(caracteres) for caracter in range(longitud))
    return token


def registraToken(token, usuario, horaCreacionToken, tabla):
    mydb = mysql.connector.connect(
        host=settings.host,
        user=settings.user,
        passwd=settings.passwd,
        database=settings.database)
    mycursor = mydb.cursor()

    if tabla == 'adminServ':
        sql = "UPDATE monitoreoAppl_adminservidores SET token= %s, horaToken=%s WHERE usuario = %s"
        val = (token, horaCreacionToken, usuario)
        mycursor.execute(sql, val)
        mydb.commit()
    if tabla == 'adminGlobal':
        sql = "UPDATE monitoreoAppl_adminglobal SET token= %s, horaToken=%s WHERE usuario = %s"
        val = (token, horaCreacionToken, usuario)
        mycursor.execute(sql, val)
        mydb.commit()


def borrarToken(usuario, tabla):
    mydb = mysql.connector.connect(
        host=settings.host,
        user=settings.user,
        passwd=settings.passwd,
        database=settings.database

    )
    mycursor = mydb.cursor()
    if tabla == 'adminServ':
        sql = "UPDATE monitoreoAppl_adminservidores SET token= %s WHERE usuario = %s"
        val = ('NULL', usuario)
        mycursor.execute(sql, val)
        mydb.commit()

    if tabla == 'adminGlobal':
        sql = "UPDATE monitoreoAppl_adminglobal SET token= %s WHERE usuario = %s"
        val = ('NULL', usuario)
        mycursor.execute(sql, val)
        mydb.commit()


def generaHash(password):
    salt = base64.b64encode(os.urandom(10)).decode('utf-8')
    hasheado = crypt.crypt(password, '$6$' + salt)
    return hasheado


def ip_checkv4(ip):
    parts = ip.split(".")
    if len(parts) < 4 or len(parts) > 4:
        return False
    else:
        while len(parts) == 4:
            try:
                a = int(parts[0])
                b = int(parts[1])
                c = int(parts[2])
                d = int(parts[3])

                if a <= 0 or a == 127:
                    return False
                elif d == 0:
                    return False
                elif a >= 255:
                    return False
                elif b >= 255 or b < 0:
                    return False
                elif c >= 255 or c < 0:
                    return False
                elif d >= 255 or c < 0:
                    return False
                else:
                    return True
            except:
                return False

@decoradores.logueadoAdminServ
def listar_monitoreo(request):
    t = 'lista_monitoreo.html'
    logging.info("Administrador de servidor logueado")
    if request.method == 'GET':
        try:
            token = regresar_token_session()

        except TokenException as err:
            return redirect('/logout/')
        try:
            monitoreo = regresar_monitoreo(request, token)
        except excepciones.monitoreoException as err:
            return redirect('/logout/')
        return render(request, t, {'monitoreo': monitoreo})


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
                raise TokenException('no se pudo recuperar el token %s' % respuesta.status_code)
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



def logout(request):
    request.session.flush()
    logging.info("Cerro sesion")
    return redirect('/login/')
