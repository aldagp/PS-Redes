#!/bin/bash

for var in $(ccdecrypt -c settings.env.cpt); do
    export "$var"
done

docker-compose up 
