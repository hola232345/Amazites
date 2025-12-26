Amazites – Analizador de Seguridad de Página Web
Descripción

Amazites es un script en Python diseñado para analizar una sola página web y generar un reporte completo de seguridad.

Funciones principales:

Verifica si la página utiliza HTTPS.

Comprueba la presencia de cabeceras de seguridad importantes (como Content-Security-Policy o X-Frame-Options).

Detecta errores visibles en la página (como SQL errors, Tracebacks o Fatal Error).

Identifica frameworks web populares, incluyendo WordPress, Laravel, Django, React y Vue.

Detecta la presencia de WAFs (Cloudflare, Sucuri, Akamai, AWS WAF).

Genera un reporte JSON con todos los hallazgos dentro de la carpeta reports/.

La salida en terminal se muestra en verde para facilitar la lectura.

Requisitos

Python 3.10 o superior

Sistema operativo: Linux, macOS o Windows

Librerías Python: requests, beautifulsoup4, rich

Instalación

Clonar el repositorio

git clone https://github.com/tu-usuario/amazites.git

cd amazites

Crear un entorno virtual (opcional, pero recomendado)

python3 -m venv amazites_env
source amazites_env/bin/activate

Instalar las dependencias

pip install -r requirements.txt

Si no cuentas con requirements.txt, puedes crear uno con:

requests
beautifulsoup4
rich

Uso

Para analizar una página web, ejecuta:

python amazites.py -u https://example.com

-u o --url indica la URL de la página que deseas analizar.

Ejemplo de salida en terminal:

Amazites analizando https://example.com

=== RESULTADOS ===
Problemas detectados: ['No HTTPS', 'Falta Content-Security-Policy']
Frameworks detectados: {'WordPress': {'version': '5.9.3'}}
WAFs detectados: ['Cloudflare']
Score de seguridad: 3

Reporte guardado: reports/amazites_example.com_20251226_123456.json

Reporte

Todos los análisis se guardan en la carpeta reports/ como archivos JSON.

Ejemplo de archivo generado: reports/amazites_example.com_20251226_123456.json

Para abrirlo:

En terminal: cat reports/amazites_example.com_20251226_123456.json | less

En navegador: arrastra el archivo JSON a tu navegador favorito para revisarlo de forma cómoda.

Contribuciones

Se aceptan contribuciones para:

Añadir soporte para más frameworks y WAFs.

Mejorar la visualización en terminal (tablas, colores, dashboards).

Generar reportes HTML interactivos
