<h1 align="center">Scopex</h1>
<p align="center">
  🇺🇸 <a href="README.md"><b>English</b></a> |
  🇪🇸 <a href="README_ES.md">Español</a>
</p>
<p align="center">
  <img width="491" height="253" alt="image" src="https://github.com/user-attachments/assets/69e17dbf-0184-4c50-ae17-ff9e40dd2df0" />
</p>
<h3 align="center">
  Scopex es una herramienta de reconocimiento rápida, basada en terminal, diseñada para analizar objetivos WordPress respetando estrictamente los límites de alcance (scope).
  Se enfoca en la visibilidad, claridad y seguridad, ayudando a bug bounty hunters y hackers éticos a comprender la superficie de ataque de WordPress antes de realizar cualquier explotación.
</h3>

---

**Herramienta ligera de reconocimiento WordPress consciente del scope**

Versión **2.2**

Esta herramienta está **diseñada exclusivamente para WordPress**. *(Esto cambiará en el futuro)*

---

## ✨ Características

### 🧭 Escaneo consciente del scope

* Aplica reglas de alcance desde un directorio dedicado `scopes/`
* Soporta:

  * Dominios raíz (`example.com`)
  * Subdominios (`admin.example.com`)
  * Comodines (`*.example.com`)
* Omite automáticamente objetivos fuera de scope
* Previene el escaneo accidental de activos no autorizados

---

### 🧠 Detección de WordPress

Detecta WordPress utilizando múltiples indicadores:

* Rutas comunes de WordPress
* Presencia de la API REST
* Análisis del contenido HTML

Si no se detecta WordPress, el escaneo se detiene de forma anticipada.

---

### 🔎 Reconocimiento de WordPress

Una vez detectado WordPress, Scopex realiza:

* Detección de versión de WordPress
* Descubrimiento pasivo de plugins:

  * Rutas directas de plugins
  * Referencias desde la API REST
* Detección de archivos sensibles expuestos:

  * `wp-config.php`
  * `.env`
  * `.git/config`
  * Logs de depuración
* Análisis de rutas de la API REST
* Enumeración de usuarios mediante la API REST (no intrusiva)
* Detección de protección contra fuerza bruta
* Búsqueda de CVEs para la versión de WordPress detectada
* Clasificación y puntuación automática de riesgo

---

### 📊 Motor de evaluación de riesgos

Cada objetivo recibe una **puntuación de riesgo (0–100)** basada en hallazgos como:

* Exposición confirmada de archivos críticos
* Enumeración de usuarios
* Falta de protección contra fuerza bruta
* Versiones de WordPress de desarrollo o inestables

Niveles de riesgo:

* `INFO`
* `LOW`
* `MEDIUM`
* `HIGH`
* `CRITICAL`

---

### 📄 Salida y reportes

Scopex genera:

* Reportes detallados por objetivo (`.txt`)
* Salida JSON opcional (`--json`)
* Un reporte resumen global para todos los objetivos escaneados

Todos los resultados se guardan dentro del directorio `output/`.

---

## 📁 Estructura del proyecto

```
ScopeX/
│
├── scopex.py
├── requirements.txt
├── README.md
│
├── scopes/
│   └── scope.txt        # archivo de scope de ejemplo
│
└── output/
    └── .gitkeep         # los archivos de salida se generan en tiempo de ejecución
```

---

## 🚀 Instalación

Clona el repositorio:

```bash
git clone https://github.com/urdev4ever/ScopeX.git
cd ScopeX
```

Instala las dependencias:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Uso

```
python scopex.py [-h] [--url URL] [--list LIST] [--scope SCOPE] [--json] [--verbose] [--silent]
```

### Escanear un solo objetivo

```bash
python scopex.py --url example.com
```

---

### Escanear respetando el scope

```bash
python scopex.py --url example.com --scope scope.txt
```

> El archivo de scope **debe estar ubicado dentro del directorio `scopes/`**. *(¡Importante!)*

---

### Escanear múltiples objetivos desde un archivo

```bash
python scopex.py --list targets.txt 
```

> Esto **NO** filtrará elementos fuera de scope.

---

### Salida JSON

```bash
python scopex.py --url example.com --json
```

---

### Modo verbose (muestra rutas de la API REST)

```bash
python scopex.py --url example.com --verbose
```

---

### Modo silencioso (sin salida por consola)

```bash
python scopex.py --url example.com --silent
```

---

## 📌 Formato del archivo de scope (`scopes/scope.txt`)

```txt
# Archivo de scope de Scopex
# Una entrada por línea
# Las líneas que comienzan con # son comentarios

example.com
*.example.com
api.example.com
admin.example.com
```

### Reglas

* ❌ NO incluir `http://` ni `https://`
* ❌ NO incluir rutas ni puertos
* ✅ Los comodines deben comenzar con `*.`

---

## 📂 Archivos de salida

Generados automáticamente dentro de `output/`:

* `{target}_{timestamp}.txt`
* `{target}_{timestamp}.json` (si `--json` está habilitado)
* `summary_{timestamp}.txt`

---

## 🎯 Ejemplo de salida

En este ejemplo, el comando utilizado fue:

```bash
python scopex.py --url wordpress.org
```

Salida:

. <img width="493" height="282" alt="image" src="https://github.com/user-attachments/assets/efc18994-345c-4f21-a7d2-66510a3a87e3" />

. <img width="474" height="536" alt="image" src="https://github.com/user-attachments/assets/f03fd50e-4a6e-40ae-9a28-1729f78090fd" />

. <img width="436" height="498" alt="image" src="https://github.com/user-attachments/assets/59a64ca1-35e2-4747-883e-5db4ea48ae2d" />

. <img width="475" height="215" alt="image" src="https://github.com/user-attachments/assets/8a5d2b96-ce3c-4282-9184-379ff411da79" />

---

## 🚫 Lo que Scopex NO hace

Scopex evita intencionalmente:

* Explotación
* Ataques de fuerza bruta
* Adivinación de contraseñas
* Inyección de payloads
* Fuzzing activo
* Crawling agresivo

Es una herramienta de **reconocimiento y evaluación**, no un framework de explotación.

---

## 🎯 Público objetivo

* Bug bounty hunters (fase temprana de recon)
* Hackers éticos
* Pentesters que necesitan visibilidad sobre WordPress
* Cualquiera que quiera **recon limpio sin herramientas infladas**

---

## ⚠️ Descargo de responsabilidad

Esta herramienta está destinada **únicamente a pruebas de seguridad autorizadas**.
El autor no se responsabiliza por el mal uso.

---

## 🧠 Filosofía

> “El recon se trata de entender la superficie — no de atacarla.”

Scopex te ayuda a:

* Mantenerte dentro del scope
* Reducir ruido
* Identificar prioridades reales
* Decidir qué probar manualmente

---

## ⭐ Contribuir

Las pull requests son bienvenidas si:

* Mejoran la precisión en la detección de WordPress o amplían técnicas de reconocimiento pasivo
* Mejoran la lógica de validación de scope o reducen falsos positivos / falsos negativos
* Mantienen la filosofía ligera y no intrusiva de la herramienta (sin explotación, sin escaneo agresivo)

---

Hecho con <3 por URDev.
