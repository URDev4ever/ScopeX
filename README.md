<h1 align="center">Scopex</h1>

<p align="center">
  🇺🇸 <a href="README.md"><b>English</b></a> |
  🇪🇸 <a href="README_ES.md">Español</a>
</p>

<p align="center">
  <img width="491" height="253" alt="image" src="https://github.com/user-attachments/assets/69e17dbf-0184-4c50-ae17-ff9e40dd2df0" />
</p>
<h3 align="center">
  Scopex is a fast, terminal-based reconnaissance tool designed to analyze WordPress targets while strictly respecting scope boundaries.
  It focuses on visibility, clarity, and safety, helping bug bounty hunters and ethical hackers understand the WordPress attack surface before doing any exploitation.
</h3>

---
**Lightweight Scope-Aware WordPress Reconnaissance Tool**

Version **2.2**

This tool is **WordPress-only by design**. _(Intended to change in the future)_

---

## ✨ Features

### 🧭 Scope-Aware Scanning

* Enforces scope rules from a dedicated `scopes/` directory
* Supports:

  * Root domains (`example.com`)
  * Subdomains (`admin.example.com`)
  * Wildcards (`*.example.com`)
* Automatically skips out-of-scope targets
* Prevents accidental scanning of unauthorized assets

---

### 🧠 WordPress Detection

Detects WordPress using multiple indicators:

* Common WordPress paths
* REST API presence
* HTML content analysis

If WordPress is not detected, the scan stops early.

---

### 🔎 WordPress Reconnaissance

Once WordPress is detected, ScopeX performs:

* WordPress version detection
* Passive plugin discovery:

  * Direct plugin paths
  * REST API references
* Detection of exposed sensitive files:

  * `wp-config.php`
  * `.env`
  * `.git/config`
  * Debug logs
* REST API route analysis
* User enumeration via REST API (non-intrusive)
* Brute force protection detection
* CVE lookup for detected WordPress version
* Automatic risk scoring and classification

---

### 📊 Risk Assessment Engine

Each target receives a **risk score (0–100)** based on findings such as:

* Confirmed critical file exposure
* User enumeration
* Missing brute force protection
* Development / unstable WordPress versions

Risk levels:

* `INFO`
* `LOW`
* `MEDIUM`
* `HIGH`
* `CRITICAL`

---

### 📄 Output & Reporting

Scopex generates:

* Detailed per-target reports (`.txt`)
* Optional JSON output (`--json`)
* A global summary report for all scanned targets

All results are saved inside the `output/` directory.

---

## 📁 Project Structure

```
ScopeX/
│
├── scopex.py
├── requirements.txt
├── README.md
├── README_ES.md
│
├── scopes/
│   └── scope.txt        # example scope file
│
└── output/
    └── .gitkeep         # output files are generated at runtime
```

---

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/urdev4ever/ScopeX.git
cd ScopeX
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Usage

```
python scopex.py [-h] [--url URL] [--list LIST] [--scope SCOPE] [--json] [--verbose] [--silent]
```

### Scan a single target

```bash
python scopex.py --url example.com
```

---

### Scan with scope enforcement

```bash
python scopex.py --url example.com --scope scope.txt
```

> The scope file **must be located inside the `scopes/` directory**. _(Important!)_

---

### Scan multiple targets from a file

```bash
python scopex.py --list targets.txt
```
> This will NOT filter out-of-scope elements.
---

### JSON output

```bash
python scopex.py --url example.com --json
```

---

### Verbose mode (show REST API routes)

```bash
python scopex.py --url example.com --verbose
```

---

### Silent mode (no console output)

```bash
python scopex.py --url example.com --silent
```

---

## 📌 Scope File Format (`scopes/scope.txt`)

```txt
# Scopex scope file
# One entry per line
# Lines starting with # are comments

example.com
*.example.com
api.example.com
admin.example.com
```

### Rules

* ❌ Do NOT include `http://` or `https://`
* ❌ Do NOT include paths or ports
* ✅ Wildcards must start with `*.`

---

## 📂 Output Files

Generated automatically inside `output/`:

* `{target}_{timestamp}.txt`
* `{target}_{timestamp}.json` (if `--json` is enabled)
* `summary_{timestamp}.txt`

---
## 🎯 Example Output

In this example the command used was:
```bash
python scopex.py --url wordpress.org
```
Output:

.
<img width="493" height="282" alt="image" src="https://github.com/user-attachments/assets/efc18994-345c-4f21-a7d2-66510a3a87e3" />

.
<img width="474" height="536" alt="image" src="https://github.com/user-attachments/assets/f03fd50e-4a6e-40ae-9a28-1729f78090fd" />

.
<img width="436" height="498" alt="image" src="https://github.com/user-attachments/assets/59a64ca1-35e2-4747-883e-5db4ea48ae2d" />

.
<img width="475" height="215" alt="image" src="https://github.com/user-attachments/assets/8a5d2b96-ce3c-4282-9184-379ff411da79" />


---

## 🚫 What Scopex Does NOT Do

Scopex intentionally avoids:

* Exploitation
* Brute-force attacks
* Password guessing
* Payload injection
* Active fuzzing
* Aggressive crawling

It is a **reconnaissance and assessment tool**, not an exploitation framework.

---

## 🎯 Intended Audience

* Bug bounty hunters (early recon phase)
* Ethical hackers
* Pentesters needing WordPress visibility
* Anyone who wants **clean recon without tool bloat**

---

## ⚠️ Disclaimer

This tool is intended **for authorized security testing only**.
The author is not responsible for misuse.

---

## 🧠 Philosophy

> “Recon is about understanding the surface — not attacking it.”

Scopex helps you:

* Stay in scope
* Reduce noise
* Identify real priorities
* Decide what to test manually

---
Made with <3 by URDev.
