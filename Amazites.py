import requests
import json
import re
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

# Inicializa la consola con color
console = Console()

requests.packages.urllib3.disable_warnings()

# ---------------- CONFIG ---------------- #

FRAMEWORK_FINGERPRINTS = {
    "WordPress": {"patterns": [r"wp-content", r"wp-includes"], "version": r"wp-content/.*?ver=([\d.]+)"},
    "Laravel": {"patterns": [r"laravel"], "header": "X-Powered-By"},
    "Django": {"patterns": [r"csrfmiddlewaretoken"], "header": "X-Frame-Options"},
    "React": {"patterns": [r"__REACT_DEVTOOLS_GLOBAL_HOOK__"]},
    "Vue": {"patterns": [r"__VUE_DEVTOOLS_GLOBAL_HOOK__"]}
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

ERROR_PATTERNS = [r"SQL syntax", r"Traceback", r"Fatal error", r"Unhandled Exception"]

WAF_PATTERNS = {
    "Cloudflare": [r"cloudflare", r"__cfduid"],
    "Sucuri": [r"sucuri", r"SUCURI"],
    "Akamai": [r"akamai", r"akamaiGHost"],
    "AWS WAF": [r"aws", r"X-Amzn-Trace-Id"]
}

# ---------------- UTILS ---------------- #

def normalize_url(url):
    if not url.startswith(("http://","https://")):
        return "http://" + url
    return url.rstrip("/")

def fetch(url):
    try:
        return requests.get(url, timeout=10, verify=False, allow_redirects=True, headers={"User-Agent":"Amazites/4.0"})
    except requests.RequestException:
        return None

# ---------------- ANALYSIS ---------------- #

def detect_frameworks(response, html):
    found = {}
    headers_text = "\n".join(f"{k}: {v}" for k,v in response.headers.items())
    for fw, rules in FRAMEWORK_FINGERPRINTS.items():
        for p in rules.get("patterns", []):
            if re.search(p, html, re.I) or re.search(p, headers_text, re.I):
                found[fw] = {"version": None}
                if "version" in rules:
                    m = re.search(rules["version"], html)
                    if m: found[fw]["version"]=m.group(1)
                if "header" in rules and rules["header"] in response.headers:
                    found[fw]["version"]=response.headers[rules["header"]]
    return found

def detect_waf(response, html):
    detected = []
    all_text = html + "\n" + "\n".join(f"{k}: {v}" for k,v in response.headers.items())
    for waf, patterns in WAF_PATTERNS.items():
        for p in patterns:
            if re.search(p, all_text, re.I):
                detected.append(waf)
                break
    return detected

def analyze_page(url):
    r = fetch(url)
    if not r:
        return {"errors":["No response"]}, {}, [], 0

    issues=[]
    if urlparse(r.url).scheme!="https": issues.append("No HTTPS")
    for h in SECURITY_HEADERS: 
        if h not in r.headers: issues.append(f"Falta {h}")
    for p in ERROR_PATTERNS:
        if re.search(p, r.text, re.I): issues.append("Errores visibles"); break

    fw = detect_frameworks(r,r.text)
    waf = detect_waf(r,r.text)
    score = len(issues)
    return issues, fw, waf, score

# ---------------- REPORT ---------------- #

def save_report(report):
    os.makedirs("reports",exist_ok=True)
    name=urlparse(report["target"]).netloc.replace(":","_")
    ts=datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    path=f"reports/amazites_{name}_{ts}.json"
    with open(path,"w",encoding="utf-8") as f:
        json.dump(report,f,indent=2,ensure_ascii=False)
    return path

# ---------------- MAIN ---------------- #

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-u","--url",help="URL objetivo", required=True)
    args = parser.parse_args()

    target = normalize_url(args.url)
    console.print(Panel.fit(f"[bold green]Amazites[/] analizando [green]{target}[/]"))

    issues, fw, waf, score = analyze_page(target)
    
    # Mostrar resultados en terminal con letras verdes
    console.print("\n[bold green]=== RESULTADOS ===[/]")
    console.print(f"[green]Problemas detectados:[/] {issues}")
    console.print(f"[green]Frameworks detectados:[/] {fw}")
    console.print(f"[green]WAFs detectados:[/] {waf}")
    console.print(f"[green]Score de seguridad:[/] {score}")

    report = {
        "tool":"Amazites",
        "target":target,
        "time":datetime.utcnow().isoformat()+"Z",
        "findings": {target: issues},
        "frameworks": fw,
        "wafs": {target: waf},
        "scores": {target: score}
    }

    path=save_report(report)
    console.print(f"\n[bold green]Reporte guardado:[/] [green]{path}[/]")

if __name__=="__main__":
    main()
