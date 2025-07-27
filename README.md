# 🔐 Analyse Automatisée des Vulnérabilités CVE à partir des Bulletins ANSSI

## 📌 Description

Ce projet Python collecte, enrichit, analyse et visualise automatiquement les vulnérabilités de sécurité publiées par l'ANSSI via flux RSS.

Fonctionnalités principales :

- Extraction des bulletins *avis* et *alertes*
- Récupération des CVE associés
- Enrichissement via les API MITRE & FIRST (EPSS)
- Consolidation des données dans un seul fichier
- Analyses de clustering (KMeans) et classification (Random Forest)
- Visualisations interactives
- Alerte par email en cas de vulnérabilité critique

---

## 📁 Structure du projet

- `configuration.py` : chemins des flux RSS et des APIs
- `main()` : pipeline de traitement complet
- `charger_flux_rss()` : collecte des bulletins ANSSI
- `extraire_cve()` : extraction des identifiants CVE
- `enrichir_cve()` : appel aux API MITRE et FIRST
- `consolider()` : fusion des informations en un seul fichier CSV
- `visualisation()` : graphiques interactifs avec Seaborn et Matplotlib
- `RandomForest()` : prédiction du risque élevé (EPSS)
- `KM()` : clustering non supervisé
- `envoyer_email()` : alerte critique par mail

---

## 🛠️ Dépendances

À installer via le fichier `requirements.txt` :

```bash
pip install -r requirements.txt
```
---

## 🚀 Exécution

Lancer le programme principal :

```bash
python main.py
```
---

## 📊 Résultats générés

- `df_bulletins.csv` : bulletins ANSSI bruts

- `df_cves.csv` : CVE extraits

- `df_enrichi.csv` : enrichissement MITRE & EPSS

- `df_consolider.csv` : base finale consolidée

- Graphiques : histogrammes, courbes temporelles, nuages de points, boxplots, heatmaps, etc.



