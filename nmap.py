import nmap
import csv
import re

def validar_ip(ip):
    """Valida si la IP ingresada tiene un formato correcto."""
    patron_ip = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    return re.match(patron_ip, ip) is not None

def validar_puertos(rango):
    """Valida si el rango de puertos ingresado es correcto (ejemplo: 1-1000)."""
    patron_rango = r"^\d{1,5}-\d{1,5}$"
    return re.match(patron_rango, rango) is not None

def escanear_puertos(ip, rango_puertos):
    """Realiza un escaneo de puertos en la IP ingresada y guarda los resultados."""
    escaner = nmap.PortScanner()
    escaner.scan(ip, rango_puertos, arguments='-sV')
    
    resultados = []
    
    for host in escaner.all_hosts():
        for puerto in escaner[host]['tcp']:
            info_puerto = escaner[host]['tcp'][puerto]
            resultados.append([
                host, puerto, info_puerto['state'], info_puerto.get('name', 'Desconocido'), info_puerto.get('version', 'No especificada')
            ])
    
    guardar_resultados(resultados)
    
    return resultados

def guardar_resultados(resultados):
    """Guarda los resultados en archivos .txt y .csv."""
    with open("resultados_escaneo.txt", "w") as txt_file:
        for r in resultados:
            txt_file.write(f"IP: {r[0]} | Puerto: {r[1]} | Estado: {r[2]} | Servicio: {r[3]} | Versión: {r[4]}\n")
    
    with open("resultados_escaneo.csv", "w", newline='') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP", "Puerto", "Estado", "Servicio", "Versión"])
        writer.writerows(resultados)

def main():
    ip = input("Ingresa la IP a escanear: ")
    while not validar_ip(ip):
        print(" IP no válida. Intenta de nuevo.")
        ip = input("Ingresa la IP a escanear: ")
    
    rango_puertos = input("Ingresa el rango de puertos a escanear (ejemplo: 1-1000): ")
    while not validar_puertos(rango_puertos):
        print(" Rango de puertos no válido. Intenta de nuevo.")
        rango_puertos = input("Ingresa el rango de puertos a escanear: ")
    
    print("⏳ Escaneando... Esto puede tardar unos segundos.")
    resultados = escanear_puertos(ip, rango_puertos)
    
    if resultados:
        print(" Escaneo completado. Los resultados se guardaron en 'resultados_escaneo.txt' y 'resultados_escaneo.csv'.")
    else:
        print(" No se encontraron puertos abiertos.")

if __name__ == "__main__":
    main()
