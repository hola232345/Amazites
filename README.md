Amazites – Analizador de Seguridad de Página Web

🔹 Descripción

Amazites es un script en Python que analiza una sola página web y genera un reporte de seguridad.

Funciones principales:

Verifica si la página usa HTTPS.

Comprueba si están presentes las cabeceras de seguridad importantes (Content-Security-Policy, X-Frame-Options, etc.).

Detecta errores visibles en la página (ej. SQL, Traceback, Fatal Error).

Detecta frameworks web populares: WordPress, Laravel, Django, React, Vue.

Detecta si la página tiene un WAF (Cloudflare, Sucuri, Akamai, AWS WAF).

Genera un reporte JSON con todos los hallazgos en la carpeta reports/.

La salida en terminal es en color verde para mejor visibilidad.

🔹 Requisitos

Python 3.10+

Sistema operativo: Linux, macOS o Windows

Librerías Python: requests, beautifulsoup4, rich

🔹 Instalación

Clonar el repositorio

git clone https://github.com/tu-usuario/amazites.git
cd amazites


Crear un entorno virtual (opcional pero recomendado)

python3 -m venv amazites_env
source amazites_env/bin/activate


Instalar dependencias

pip install -r requirements.txt


Si no tienes requirements.txt, puedes crear uno con:

requests
beautifulsoup4
rich

🔹 Uso

Analizar una página web:

python amazites.py -u https://example.com


-u o --url: URL de la página a analizar.

Ejemplo de salida en terminal (toda en verde):

Amazites analizando https://example.com

=== RESULTADOS ===
Problemas detectados: ['No HTTPS', 'Falta Content-Security-Policy']
Frameworks detectados: {'WordPress': {'version': '5.9.3'}}
WAFs detectados: ['Cloudflare']
Score de seguridad: 3

Reporte guardado: reports/amazites_example.com_20251226_123456.json

🔹 Reporte

Todos los análisis se guardan en la carpeta reports/ como JSON.

Ejemplo de archivo generado:

reports/amazites_example.com_20251226_123456.json


Para abrirlo:

En terminal:

cat reports/amazites_example.com_20251226_123456.json | less


En navegador:

Arrastra el archivo JSON a tu navegador favorito para revisarlo de forma más cómoda.

🔹 Contribuciones

Se aceptan contribuciones para:

Añadir soporte de más frameworks y WAFs.

Mejorar la visualización en terminal (tablas, colores, dashboards).

Agregar generación de reportes HTML interactivos.
