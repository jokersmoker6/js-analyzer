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

Instalar Node.js (si no lo tienes):

      curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
      sudo apt-get install -y nodejs

instalación global pycryptodome:

    sudo pip install pycryptodome --break-system-packages # Funciones criptográficas
    
Verificar:
      
      python3 -c "from Crypto.Cipher import AES; print('OK')"

instalación global deobfuscator:

      sudo npm install -g javascript-deobfuscator  # Para desofuscación

Verificar:

      javascript-deobfuscator --version


🛡️ Modo de uso

  Obtendrás un resumen detallado con el --output

      chmod +x js_forensics.py

      python js_forensics.py archivo.js --output report_final.html

![image](https://github.com/user-attachments/assets/5a3ce6aa-0841-420a-b5c8-42354033c9e8)

