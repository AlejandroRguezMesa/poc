# Gestión de certificados con Ansible — ULPGC

PoC de automatización del ciclo de vida de certificados X.509.

## Estructura
- `playbooks/` — orquestación (descubrimiento, renovación, reubicación, retirada)
- `roles/` — lógica reutilizable
- `inventory/` — hosts y variables
- `scripts/` — utilidades (generador de host_vars)

## Requisitos
- Ansible Core 2.16+
- Colecciones: community.crypto, community.general, ansible.posix
- Python: cryptography, PyYAML

## Uso
Ver documentación en `docs/`.
