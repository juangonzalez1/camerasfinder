# Cameras Finder
## Descripción
Herramienta destinada a la obtención de información y explotación de cámaras IP utilizando para ello el motor de búsqueda Shodan.

**Funcionalidades**
- Permitir al usuario realizar una búsqueda de cualquier dispositivo, mediante la introducción de una cadena de texto identificativa.
- Enumerar de modo automático los principales resultados de cámaras ip accesibles a través de internet.
- Enumerar y listar servicios, puertos y huellas digitales que tiene asociado dicho dispositivo.
- Obtener un listado de las principales vulnerabilidades o _CVEs_ que afectan a dicha cámara ip.
- Comprobar si un dispositivo tiene algún servicio o página web accesible de forma automática.
- Lanzamiento desde la propia herramienta de un escaneo de servicios mediante _nmap_.
- Ejecución o explotación de alguna vulnerabilidad que afecta a dicha cámara para conseguir acceso a la cámara.
- Mostrar los resultados obtenidos en una salida límpia y amigable, así como tener la posibilidad de almacenar en un fichero dichos resultados para el futuro análisis o consulta.

## Instalación

```bash
# git clone https://github.com/juangonzalez1/TFM
# cd TFM
# pip install -r requirements.txt
```



Es necesario disponer de una **API KEY** de Shodan.

## Uso
- **Opción _-a_**: Se realiza una búsqueda de las principales cámaras IP accesibles a través de internet. Esta búsqueda se realiza a partir de una serie de queries _hardcodeadas_ en el código, las cuales hacen referencia de los principais modelos de cámaras del mercado.

- **Opción _-f_**: Se realiza una búsqueda concreta de un módelo de cámara mediante la introducción de una cadena de texto o query proporcionada por el usuario.

- **Opción _-k_**: El usuario establece la API KEY de _Shodan_, necesaria para el correcto funcionamento de **CamerasFinder**.

- **Opción _-c_**: Filtra los resultados de la búsqueda en base a su localización, en concreto al nombre de una ciudad.

- **Opción _-o_**: Filtra los resultados de la búsqueda en base a su localización, en concreto al nombre de un país. En este caso es necesario la utilización de los códigos alfabéticos de cada pais, siendo por ejemplo el de España _"ES"_.

- **Opción _-l_**: Limita el número de resultados mostrados para cada búsqueda. Por defecto este valor está acotado a 20 resultados.

- **Opción _-t_**: Establece el ficheiro de _log_ en el que se van a almacenar los resultados obtenidos, en formato texto.
