Este script se basa en poder realizar un análisis estático hacia archivos .js enfocado en:

1.	Detección de Ofuscación:
o	Identifica código empaquetado (eval, p,a,c,k,e,d)
o	Detecta codificación Hex/Base64
o	Intenta desofuscar automáticamente

3.	Extracción de Secretos:
o	50+ patrones para API keys, JWTs, credenciales
o	Claves criptográficas (AES, DES)
o	Credenciales de bases de datos

5.	Análisis Criptográfico:
o	Detecta uso de CryptoJS, WebCrypto, forge
o	Identifica claves e vectores de inicialización
o	Revisa modos de operación (CBC, GCM, etc.)

7.	Análisis de Red:
o	Extrae endpoints API
o	Identifica headers de autenticación

9.	Informe Profesional:
o	Reporte HTML con sintaxis resaltada
o	Clasificación por severidad
o	Contexto de los hallazgos

Riquisitos

pip install pycryptodome jinja2
npm install -g javascript-deobfuscator  # Para desofuscación


Modo de uso

Obtendras un resumen detallado con el --output

python js_forensics.py archivo.js --output informe.html
