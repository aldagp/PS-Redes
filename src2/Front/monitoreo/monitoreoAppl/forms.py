from django import forms
from django.forms import ModelForm
from monitoreoAppl.models import adminServidores,servidores
import datetime

class adminServerForm(forms.ModelForm):

    usuario = forms.CharField(min_length=3, max_length=20)
    password = forms.CharField(min_length=3, max_length=30)
    chatID = forms.CharField(min_length=9, max_length=9)
    class Meta:
        model = adminServidores
        fields = ['usuario', 'password', 'token', 'horaToken', 'chatID']
  

class servidoresForm(forms.ModelForm):

    class Meta:
        model = servidores
        fields = ['adminServ', 'nombre', 'direccionIp', 'usuarioAPI', 'passwordAPI']