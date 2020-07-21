FROM python:3.6

RUN mkdir /dependencias

COPY requeriments.txt /dependencias

RUN pip3 install -r /dependencias/requeriments.txt

ENV SECRET_KEY_SERVICIO2=""
ENV DB_NAME_SERVICIO2=""
ENV DB_USER_SERVICIO2=""
ENV DB_PASSWORD_SERVICIO2=""
ENV DB_HOST_SERVICIO2=""
ENV DB_PORT_SERVICIO2=3306
ENV MYSQL_ROOT_PASSWORD=""
ENV MYSQL_DATABASE=""


RUN mkdir /code
RUN mkdir /start

COPY ./run.sh /start
RUN chmod +x /start/run.sh

WORKDIR /code

CMD /start/run.sh
