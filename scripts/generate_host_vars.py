#!/usr/bin/env python3
"""
Genera host_vars/<host>.yml a partir de los reportes JSON del descubrimiento.

Mejoras respecto a versiones anteriores:
  - Distingue certs PEM de keystores PKCS#12. Los .p12 generan un bloque
    `keystores:` con `keystore_dest` y `keystore_password: TODO_*`, no
    intentan emparejarse con una key adyacente.
  - Inferencia de puerto en cascada:
      1) Cruce de fingerprints (lo más fiable).
      2) Único puerto en escucha con proceso conocido.
      3) Puerto típico por servicio (nginx/apache/httpd→443, tomcat→8443).
      4) TODO_puerto si nada cuadra.
"""

import json
import glob
import os
import re
import argparse
import yaml
from datetime import datetime
from pathlib import Path

SERVICE_MAP = {
    "nginx":   "nginx",
    "apache2": "apache2",
    "httpd":   "httpd",
    "java":    "tomcat",
    "tomcat":  "tomcat",
}

DEFAULT_PORT_BY_SERVICE = {
    "nginx":   "443",
    "apache2": "443",
    "httpd":   "443",
    "tomcat":  "8443",
}


def extract_path(c):
    item = c.get("item", {})
    if isinstance(item, dict):
        if "path" in item:
            return item["path"]
        inner = item.get("item", {})
        if isinstance(inner, dict) and "path" in inner:
            return inner["path"]
    return ""


def file_fingerprint(c):
    fp = c.get("fingerprints", {}).get("sha256", "")
    return fp.replace(":", "").upper()


def is_keystore(path):
    return path.lower().endswith((".p12", ".pfx"))


def infer_service_and_port(path, served_fps, listening, file_fp):
    """
    Inferencia en cascada del (servicio, puerto).
    """
    # 1) Cruce de fingerprints (lo más fiable)
    for port, served_fp in (served_fps or {}).items():
        if served_fp.upper() == file_fp:
            proc = (listening or {}).get(port, "")
            service = SERVICE_MAP.get(proc.lower(), proc)
            return (service, port)

    # 2) Si hay UN solo puerto en escucha con proceso conocido, asumirlo
    known_listening = {
        p: SERVICE_MAP.get(proc.lower())
        for p, proc in (listening or {}).items()
        if proc.lower() in SERVICE_MAP
    }
    if len(known_listening) == 1:
        port, service = list(known_listening.items())[0]
        return (service, port)

    # 3) Fallback por ruta + puerto típico del servicio
    service_by_path = None
    if path.startswith("/etc/nginx/"):
        service_by_path = "nginx"
    elif path.startswith("/etc/apache2/"):
        service_by_path = "apache2"
    elif path.startswith("/etc/httpd/") or path.startswith("/etc/pki/tls/"):
        service_by_path = "httpd"
    elif "/tomcat" in path or is_keystore(path):
        service_by_path = "tomcat"

    if service_by_path:
        return (service_by_path, DEFAULT_PORT_BY_SERVICE.get(service_by_path, "TODO_puerto"))

    return ("TODO_verificar", "TODO_puerto")


def normalize_mode(mode_val):
    if not mode_val:
        return "0644"
    try:
        if isinstance(mode_val, str):
            return mode_val[-4:] if len(mode_val) >= 4 else mode_val
        return oct(mode_val)[-4:]
    except Exception:
        return "0644"


def safe_name_from_cn(cn):
    return re.sub(r"[^a-z0-9-]+", "-", cn.lower()).strip("-") or "cert"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports-dir", required=True)
    ap.add_argument("--host-vars-dir", required=True)
    ap.add_argument("--certs-input-dir", default="files/certs_input")
    args = ap.parse_args()

    Path(args.host_vars_dir).mkdir(parents=True, exist_ok=True)

    per_host = {}
    for f in glob.glob(f"{args.reports_dir}/*.json"):
        for c in json.load(open(f)):
            per_host.setdefault(c["host"], []).append(c)

    if not per_host:
        print(f"No se encontraron reportes en {args.reports_dir}/")
        return

    for host, entries in per_host.items():
        certificates = []
        keystores = []

        for c in entries:
            path = extract_path(c)
            file_fp = file_fingerprint(c)
            served = c.get("served_fingerprints", {})
            listening = c.get("listening_ports", {})
            stats = c.get("file_stats", {}).get(path, {})

            service, port = infer_service_and_port(path, served, listening, file_fp)
            cn = c["subject"].get("commonName", "")
            name = safe_name_from_cn(cn)

            basename = os.path.basename(path)
            base_noext = re.sub(r"\.(crt|pem|p12|pfx)$", "", basename)

            try:
                port_value = int(port)
            except (TypeError, ValueError):
                port_value = port  # deja "TODO_puerto" como string

            if is_keystore(path):
                # Esquema para Tomcat / keystores PKCS#12
                ks_entry = {
                    "name":              name,
                    "cert_src":          "{{ playbook_dir }}/../" + f"{args.certs_input_dir}/{base_noext}.crt",
                    "key_src":           "{{ playbook_dir }}/../" + f"{args.certs_input_dir}/{base_noext}.key",
                    "keystore_dest":     path,
                    "keystore_password": "TODO_obtener_de_vault",
                    "keystore_alias":    name,
                    "owner":             stats.get("pw_name", "tomcat"),
                    "group":             stats.get("gr_name", "tomcat"),
                    "mode":              normalize_mode(stats.get("mode")),
                    "service":           service or "tomcat",
                    "validate": {
                        "host": "{{ ansible_host }}",
                        "port": port_value,
                        "sni":  cn,
                    },
                }
                keystores.append(ks_entry)
            else:
                # Esquema PEM normal (nginx, apache, httpd...)
                key_path = c.get("cert_to_key", {}).get(path, "") or "TODO_completar"
                cert_entry = {
                    "name":      name,
                    "cert_src":  "{{ playbook_dir }}/../" + f"{args.certs_input_dir}/{base_noext}.crt",
                    "key_src":   "{{ playbook_dir }}/../" + f"{args.certs_input_dir}/{base_noext}.key",
                    "cert_dest": path,
                    "key_dest":  key_path,
                    "owner":     stats.get("pw_name", "root"),
                    "group":     stats.get("gr_name", "root"),
                    "cert_mode": normalize_mode(stats.get("mode")),
                    "key_mode":  "0600",
                    "service":   service or "TODO_verificar",
                    "validate": {
                        "host": "{{ ansible_host }}",
                        "port": port_value,
                        "sni":  cn,
                    },
                }
                certificates.append(cert_entry)

        # Escribir host_vars
        out_path = Path(args.host_vars_dir) / f"{host}.yml"
        if out_path.exists():
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            bak = out_path.with_suffix(f".yml.bak.{ts}")
            out_path.rename(bak)
            print(f"  backup previo: {bak.name}")

        content = {}
        if certificates:
            content["certificates"] = certificates
        if keystores:
            content["keystores"] = keystores

        with open(out_path, "w") as fh:
            fh.write("---\n")
            fh.write("# Generado automaticamente por generate_host_vars.py\n")
            fh.write(f"# Fecha: {datetime.now().isoformat(timespec='seconds')}\n")
            fh.write("# Revisa entradas TODO_* antes de usar en renovaciones.\n\n")
            yaml.safe_dump(
                content, fh,
                default_flow_style=False, sort_keys=False, indent=2,
                allow_unicode=True,
            )

        # Recuento de TODOs
        flat = json.dumps(content)
        todos = flat.count("TODO_")
        status = f"[{todos} TODO]" if todos else "[OK]"

        n_certs = len(certificates)
        n_ks = len(keystores)
        parts = []
        if n_certs:
            parts.append(f"{n_certs} PEM")
        if n_ks:
            parts.append(f"{n_ks} keystore")
        what = ", ".join(parts) if parts else "0 certs"

        print(f"  {host}: {what} -> {out_path.name}  {status}")

    print(f"\nGenerados en {args.host_vars_dir}")


if __name__ == "__main__":
    main()
