"""monitoreo URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from monitoreo.views import *
from monitoreo.views import funcionesAdminGlobal
from monitoreo.views import actualizarAdminServ


urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', login),
    path('token/', token),
    path('logout/', logout),
    path('funcionesAdminGlobal/', funcionesAdminGlobal, name= "funcionesAdminGlobal"),
    path('registrarAdminServ/', registrarAdminServ),
    path('actualizarAdminServ/<id>/', actualizarAdminServ, name= "actualizarAdminServ"), #(?P<id>\d+)/$
    path('actualizarServ/<adminServ_id>', actualizarServer, name="actualizarServer"),
    path('eliminarAdminServ/<id>/', eliminarAdminServ, name= "eliminarAdminServ"),
    path('eliminarServ/<adminServ_id>/', eliminarServ, name= "eliminarServ"),
    path('asociarServ/', asociarServ),
    path('funcionesAdminServ/', listar_monitoreo),
    path('verServidor/', mostrarServer, name="verServidor"),
    path('registrarServer/', registrarServer, name="registrarServer")
]

