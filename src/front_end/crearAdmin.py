import mysql.connector
import datetime
hora = datetime.datetime.NOW()
mydb = mysql.connector.connect(
#  DB_HOST="localhost",
#  DB_USER="redes2020",
#  DB_PASSWORD="redes2020",
#  DB_NAME="front_end_monitor",

	host="localhost",
	user="redes2020",
	password="redes2020",
	database="front_end_monitor"
)

mycursor = mydb.cursor()

sql = "INSERT INTO bd_adminGlobal (usuario, password, token, horaToken, chatID) VALUES (%s,%s,%s,%s,%s)"
val = ('carlosuh', '$6$I+NBPWlL+5dd3w==$oltj/Dv7SOZtJzDnYL0GvW49ikYtgAlrIQrk8fYyw9xCOXdb/WfTibqcQo5nYgBsZ9zccuOKZV5rORadkXaG/0', 'NULL', hora, '@torkeenks')
mycursor.execute(sql, val)
mydb.commit()
