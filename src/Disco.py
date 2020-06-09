import psutil,os

# Indicamos la ruta del disco.
disk_usage = psutil.disk_usage("C:\\")
memory = psutil.virtual_memory()
CPU = psutil.cpu_percent(interval=1)
def to_gb(bytes):
    "Convierte bytes a gigabytes."
    return bytes / 1024**3
print ("Información de disco")
print ("")
print("Espacio total: {:.2f} GB.".format(to_gb(disk_usage.total)))
print("Espacio libre: {:.2f} GB.".format(to_gb(disk_usage.free)))
print("Espacio usado: {:.2f} GB.".format(to_gb(disk_usage.used)))
print("Porcentaje de espacio usado: {}%.".format(disk_usage.percent))
print ("")
print ("Información de memoria")
print("Porcentaje de memoria usada es: {}%.".format(memory.percent))
print ("")
print("Información del procesador")
print("Porcentaje de CPU usado es: {}%.".format(CPU))