🛡️ Este script se basa en poder realizar un análisis estático hacia archivos .js enfocado en:

1.	Detección de Ofuscación:
   
- Identifica código empaquetado (eval, p,a,c,k,e,d)
- Detecta codificación Hex/Base64
- Intenta desofuscar automáticamente

2.	Extracción de Secretos:
   
- 50+ patrones para API keys, JWTs, credenciales
- Claves criptográficas (AES, DES)
- Credenciales de bases de datos

3.	Análisis Criptográfico:
   
- Detecta uso de CryptoJS, WebCrypto, forge
- Identifica claves e vectores de inicialización
- Revisa modos de operación (CBC, GCM, etc.)

4.	Análisis de Red:
   
- Extrae endpoints API
- Identifica headers de autenticación

5.	Informe Profesional:
    
- Reporte HTML con sintaxis resaltada
- Clasificación por severidad
- Contexto de los hallazgos

🛡️ Riquisitos

    pip install pycryptodome jinja2
    npm install -g javascript-deobfuscator  # Para desofuscación


🛡️ Modo de uso

  Obtendrás un resumen detallado con el --output

    python js_forensics.py archivo.js --output informe.html
