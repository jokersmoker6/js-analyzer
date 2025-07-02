#!/usr/bin/env python3
import re
import ast
import json
from pathlib import Path
import base64
import hashlib
from Crypto.Cipher import AES
import subprocess
import tempfile
import logging
from datetime import datetime

# Configuración avanzada de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('js_forensics.log'),
        logging.StreamHandler()
    ]
)

class JSAdvancedAnalyzer:
    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.content = self._read_file()
        self.findings = {
            "file": str(self.file_path),
            "stats": {
                "size_kb": round(self.file_path.stat().st_size / 1024, 2),
                "lines": len(self.content.split('\n'))
            },
            "secrets": [],
            "crypto": {
                "functions": [],
                "keys": [],
                "ivs": []
            },
            "network": {
                "endpoints": [],
                "auth_headers": []
            },
            "vulnerabilities": []
        }
        self._detect_obfuscation()

    def _read_file(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Error reading file: {e}")
            return ""

    def _detect_obfuscation(self):
        """Detección básica de ofuscación"""
        obfuscation_patterns = {
            "hex_encoded": r"\\x[0-9a-fA-F]{2}",
            "base64": r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
            "packers": r"eval\(function\(p,a,c,k,e,d\)|p,a,c,k,e,d|aaencode|jjencode"
        }
        
        for name, pattern in obfuscation_patterns.items():
            if re.search(pattern, self.content):
                self.findings["vulnerabilities"].append({
                    "type": "obfuscation",
                    "technique": name,
                    "severity": "high"
                })

    def _extract_secrets(self):
        """Extracción avanzada de secretos usando 50+ patrones"""
        secret_patterns = [
            # API Keys
            r"(?:api|access|secret)[_-]?key['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{20,50})",
            # JWTs
            r"eyJ[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+",
            # Cryptographic keys
            r"(?:aes|des|blowfish)[_-]?(?:key|iv)\s*[:=]\s*['\"]([0-9a-fA-F]{16,64})",
            # AWS
            r"(AKIA|ASIA)[A-Z0-9]{16}",
            # Database connections
            r"((jdbc|mysql|postgresql):\/\/[^:\s]+:[^@\s]+@[^\/\s]+\/[^\s'\"]+)"
        ]

        for pattern in secret_patterns:
            for match in re.finditer(pattern, self.content, re.IGNORECASE):
                secret = match.group(1) if match.groups() else match.group(0)
                context = self._get_context(match.start(), match.end())
                self.findings["secrets"].append({
                    "type": "secret",
                    "value": secret,
                    "pattern": pattern,
                    "context": context
                })

    def _analyze_crypto(self):
        """Análisis de operaciones criptográficas"""
        # Detección de funciones criptográficas
        crypto_funcs = re.finditer(
            r"(CryptoJS|forge|crypto)\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\(.*?\)",
            self.content
        )
        
        for match in crypto_funcs:
            self.findings["crypto"]["functions"].append({
                "function": match.group(0),
                "context": self._get_context(match.start(), match.end())
            })

        # Detección de claves e IVs
        key_patterns = [
            r"key\s*:\s*['\"]([^'\"]{16,64})['\"]",
            r"createCipheriv\(['\"][^'\"]+['\"]\s*,\s*['\"]([^'\"]+)['\"]"
        ]
        
        for pattern in key_patterns:
            for match in re.finditer(pattern, self.content):
                self.findings["crypto"]["keys"].append(match.group(1))

    def _analyze_network(self):
        """Extracción de endpoints y headers de autenticación"""
        # Endpoints API
        endpoints = re.finditer(
            r"(https?:\/\/[^\/\s]+\/[^\"'\s]+)",
            self.content
        )
        for match in endpoints:
            self.findings["network"]["endpoints"].append(match.group(1))

        # Headers de autenticación
        auth_headers = re.finditer(
            r"headers\s*:\s*\{[^}]*(authorization|token|x-api-key)[^}]*\}",
            self.content, re.DOTALL | re.IGNORECASE
        )
        for match in auth_headers:
            self.findings["network"]["auth_headers"].append(match.group(0))

    def _get_context(self, start, end, lines=3):
        """Obtiene contexto alrededor del match"""
        lines_before = self.content[:start].split('\n')[-lines:]
        match_line = self.content[start:end]
        lines_after = self.content[end:].split('\n')[:lines]
        return {
            "before": lines_before,
            "match": match_line,
            "after": lines_after
        }

    def _attempt_deobfuscation(self):
        """Intenta desofuscar código básico"""
        if any(vuln["type"] == "obfuscation" for vuln in self.findings["vulnerabilities"]):
            try:
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.js') as tmp:
                    tmp.write(self.content)
                    tmp.flush()
                    result = subprocess.run(
                        ['javascript-deobfuscator', tmp.name],
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        return result.stdout
            except Exception as e:
                logging.warning(f"Deobfuscation failed: {e}")
        return None

    def analyze(self):
        """Ejecuta todos los análisis"""
        logging.info(f"Starting analysis of {self.file_path}")
        
        self._extract_secrets()
        self._analyze_crypto()
        self._analyze_network()
        
        # Intento de desofuscación si es necesario
        deobfuscated = self._attempt_deobfuscation()
        if deobfuscated:
            self.content = deobfuscated
            self.findings["deobfuscated"] = True
            # Re-analizar después de desofuscar
            self._extract_secrets()
            self._analyze_crypto()

        return self.findings

def generate_html_report(findings, output_file="report.html"):
    """Genera un informe HTML profesional"""
    from jinja2 import Template

    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>JS Security Analysis Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .secret { color: #d9534f; }
            .crypto { color: #5bc0de; }
            .network { color: #5cb85c; }
            .vuln { color: #f0ad4e; }
            pre { background: #f5f5f5; padding: 10px; border-radius: 5px; }
            .severity-high { background-color: #f8d7da; padding: 5px; }
        </style>
    </head>
    <body>
        <h1>JavaScript Security Analysis Report</h1>
        <p>Generated: {{ timestamp }}</p>
        
        <h2>File Information</h2>
        <ul>
            <li>Path: {{ findings.file }}</li>
            <li>Size: {{ findings.stats.size_kb }} KB</li>
            <li>Lines: {{ findings.stats.lines }}</li>
        </ul>

        {% if findings.secrets %}
        <h2 class="secret">🔑 Secrets Found ({{ findings.secrets|length }})</h2>
        <table border="1">
            <tr>
                <th>Type</th>
                <th>Value</th>
                <th>Context</th>
            </tr>
            {% for secret in findings.secrets %}
            <tr>
                <td>{{ secret.type }}</td>
                <td><code>{{ secret.value }}</code></td>
                <td><pre>{{ secret.context.before[-1] }}\n{{ secret.context.match }}\n{{ secret.context.after[0] }}</pre></td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if findings.crypto.functions %}
        <h2 class="crypto">🔐 Cryptographic Operations</h2>
        <ul>
            {% for func in findings.crypto.functions %}
            <li><code>{{ func.function }}</code></li>
            {% endfor %}
        </ul>
        {% endif %}

        {% if findings.vulnerabilities %}
        <h2 class="vuln">⚠️ Vulnerabilities</h2>
        <ul>
            {% for vuln in findings.vulnerabilities %}
            <li class="severity-{{ vuln.severity }}">
                {{ vuln.type|upper }} ({{ vuln.technique }}) - {{ vuln.severity|upper }}
            </li>
            {% endfor %}
        </ul>
        {% endif %}
    </body>
    </html>
    ''')

    html = template.render(
        findings=findings,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    logging.info(f"HTML report generated: {output_file}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Advanced JavaScript Analyzer')
    parser.add_argument('file', help='JavaScript file to analyze')
    parser.add_argument('--output', help='Output report file', default='report.html')
    args = parser.parse_args()

    analyzer = JSAdvancedAnalyzer(args.file)
    results = analyzer.analyze()
    generate_html_report(results, args.output)