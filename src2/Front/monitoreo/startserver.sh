#!/bin/bash

for var in $(ccrypt -d -c settings.env.cpt); do
	export "$var"

done
#python3 manage.py createsuperuser


python3.6 manage.py runserver 8000
