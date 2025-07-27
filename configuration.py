import os

# 1) On récupère le dossier où se trouve ce fichier configuration.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 2) On pointe DATA_ROOT sur le dossier data_pour_TD_final **absolu**
DATA_ROOT = os.path.join(BASE_DIR, "data_pour_TD_final")

# 3) On construit ensuite les sous-dossiers
RSS_PATHS = {
    "avis":    "https://www.cert.ssi.gouv.fr/avis/feed/",
    "alertes": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

ENRICH_PATHS = {
    "mitre": "https://cveawg.mitre.org/api/cve/",
    "first": "https://api.first.org/data/v1/epss?cve=",
}

PAUSE = 1.5  # secondes