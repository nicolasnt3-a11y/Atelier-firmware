"""Génère automotive.yar (tables de CRC et constantes SHE).

    python automotive_yar.py > automotive.yar

Pour ajouter un CRC : une ligne dans CRCS (table_msb pour un CRC non réfléchi,
table_lsb avec le polynôme réfléchi sinon).
"""
import sys


def table_msb(poly, width):
    top, mask = 1 << (width - 1), (1 << width) - 1
    out = []
    for i in range(256):
        c = i << (width - 8)
        for _ in range(8):
            c = ((c << 1) ^ poly) if c & top else (c << 1)
        out.append(c & mask)
    return out


def table_lsb(rpoly, width):
    out = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ rpoly if c & 1 else c >> 1
        out.append(c)
    return out


def hexseq(entries, width, endian):
    n = width // 8
    return " ".join(e.to_bytes(n, endian).hex().upper() for e in entries)


CRCS = [
    # nom, description, largeur, table, entrées utilisées
    ("CRC8_SAE_J1850", "CRC-8 SAE J1850 (AUTOSAR E2E profils 1/2/11, OBD)", 8, table_msb(0x1D, 8)),
    ("CRC8_H2F", "CRC-8H2F (AUTOSAR E2E profil 2)", 8, table_msb(0x2F, 8)),
    ("CRC16_CCITT", "CRC-16 CCITT 0x1021 (AUTOSAR E2E profils 5/6/11, UDS, XCP)", 16, table_msb(0x1021, 16)),
    ("CRC16_ARC", "CRC-16 IBM/ARC 0x8005 (Modbus, divers calculateurs)", 16, table_lsb(0xA001, 16)),
    ("CRC32_IEEE", "CRC-32 IEEE 802.3 (AUTOSAR Crc_CalculateCRC32, zip, Ethernet)", 32, table_lsb(0xEDB88320, 32)),
    ("CRC32_P4", "CRC-32P4 0xF4ACFB13 (AUTOSAR E2E profil 4)", 32, table_lsb(0xC8DF352F, 32)),
    ("CRC32_C", "CRC-32C Castagnoli (iSCSI, ext4, certains bootloaders)", 32, table_lsb(0x82F63B78, 32)),
    ("CRC64_ECMA", "CRC-64 ECMA-182 (AUTOSAR E2E profil 7)", 64, table_lsb(0xC96C5795D7870F42, 64)),
]

out = ["""/*
    Règles de l'Atelier Firmware pour les calculateurs automobiles.
    Fichier généré : tables de CRC précalculées (en petit- et gros-boutiste,
    entrées 1 à 8 ou 16) et constantes de la norme SHE (Secure Hardware Extension).
    Une table de CRC indique la présence d'un contrôle d'intégrité (protection
    E2E des messages CAN, vérification de la mémoire, du téléchargement…).
*/
"""]

for name, desc, width, tab in CRCS:
    count = 16 if width == 8 else 8 if width <= 32 else 4
    entries = tab[1:1 + count]
    strings = []
    if width == 8:
        strings.append(f"$t = {{ {hexseq(entries, 8, 'big')} }}")
    else:
        strings.append(f"$le = {{ {hexseq(entries, width, 'little')} }}")
        strings.append(f"$be = {{ {hexseq(entries, width, 'big')} }}")
    body = "\n        ".join(strings)
    out.append(f"""rule AUTO_{name}_table
{{
    meta:
        description = "Table de {desc}"
        family = "crc"
    strings:
        {body}
    condition:
        any of them
}}
""")

# SHE : constantes de dérivation de clés (SHE functional specification, HIS / AUTOSAR).
she = {
    "KEY_UPDATE_ENC_C": "010153484500800000000000000000B0",
    "KEY_UPDATE_MAC_C": "010253484500800000000000000000B0",
    "DEBUG_KEY_C": "010353484500800000000000000000B0",
}
strings = "\n        ".join(f"${k.lower()} = {{ {' '.join(v[i:i+2] for i in range(0, 32, 2))} }}" for k, v in she.items())
out.append(f"""rule AUTO_SHE_constants
{{
    meta:
        description = "Constantes SHE (mise à jour des clés du module de sécurité du calculateur)"
        family = "she"
    strings:
        {strings}
    condition:
        any of them
}}
""")

sys.stdout.reconfigure(encoding="utf-8", newline="\n")
print("\n".join(out), end="")
