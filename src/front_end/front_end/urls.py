"""front_end URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""

#from django.conf.urls import url
#from django.contrib import admin

#urlpatterns = [
#    url(r'^admin/', admin.site.urls),
#]

from django.contrib import admin
from django.conf.urls import url
from front_end.views import * 
#from django.urls import path

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^login/', login),
    url(r'^token/', token),
    url(r'^funcionesAdminGlobal/', funcionesAdminGlobal),
    url(r'^funcionesAdminServ/', funcionesAdminServ),
    url(r'^registrarAdminServ/', registrarAdminServ),
    url(r'^actualizarAdminServ/', actualizarAdminServ),
    url(r'^eliminarAdminServ/', eliminarAdminServ),
    url(r'^asociarServ/', asociarServ),
    url(r'^lista', lista),
    url(r'^listar_monitoreo/', listar_monitoreo),
#    url(r'^registroAdmin', registroAdmin),
#    url(r'^$', ambos),
    url(r'^logout/', logout),
]