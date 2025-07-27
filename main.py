from configuration import RSS_PATHS, PAUSE
from configuration import ENRICH_PATHS
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import feedparser
import requests
import re
from concurrent.futures import ThreadPoolExecutor
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay, roc_curve, roc_auc_score, silhouette_score
from sklearn.cluster import KMeans
from sklearn.preprocessing import LabelEncoder,StandardScaler
from sklearn.decomposition import PCA
from email.mime.text import MIMEText
import smtplib
import time

def pause():
    time.sleep(PAUSE)
    
def charger_flux_rss():
    bulletins=[]
    for rss_feed_key,rss_feed_values in RSS_PATHS.items():
        rss_feed=feedparser.parse(rss_feed_values)
        for entry in rss_feed.entries:
            identifiant = entry.link.rstrip('/').split('/')[-1]
            ligne={
                'ID ANSSI': identifiant,
                'Titre':entry.title,
                'Description':entry.description,
                'Lien':entry.link,
                'Date':entry.published,
                "Type":rss_feed_key  
            }
            bulletins.append(ligne)
        #pause()
    df = pd.DataFrame(bulletins)
    df.to_csv('df_bulletins.csv', index=False, encoding='utf-8')
    print(f"▶ {len(df)} bulletins chargés.")
    return df

def extraire_cve(df_bulletins):
    cve=[]
    MOTIF_CVE = "/json/"
    for bulletin_index, bulletin_ligne in df_bulletins.iterrows():
        if pd.notna(bulletin_ligne['Lien']):
            url=bulletin_ligne['Lien']+MOTIF_CVE
            response = requests.get(url)
            data = response.json()
            #Extraction des CVE reference dans la clé cves du dict data
            ref_cves=list(data["cves"])
            #attention il s’agit d’une liste des dictionnaires avec name et url comme clés
            print( "CVE references ", ref_cves)
            # Extraction des CVE avec une regex
            cve_pattern = r"CVE-\d{4}-\d{4,7}"
            cve_list = list(set(re.findall(cve_pattern, str(data))))
            print("CVE trouves :", cve_list)
            for cve_id in cve_list:
                    cve.append({
                        "ID ANSSI": bulletin_ligne['ID ANSSI'],
                        "Type": bulletin_ligne['Type'],
                        "CVE": cve_id
                    })
            #pause()
    df_cves = pd.DataFrame(cve)
    df_cves.to_csv('df_cves.csv', index=False, encoding='utf-8')
    print(f"▶ {len(df_cves)} references CVE extraites.")
    return df_cves

def enrichir_single_cve(cve_ligne):
    if cve_ligne["CVE"]:
        mitre_list = mitre(cve_ligne["CVE"])
        epss_score = first(cve_ligne["CVE"])
        return {
            "ID ANSSI": cve_ligne["ID ANSSI"],
            "Type": cve_ligne["Type"],
            "CVE": cve_ligne["CVE"],
            "Mitre": mitre_list,
            "EPSS": epss_score
        }

def enrichir_cve(df_cve):
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(enrichir_single_cve, df_cve.to_dict('records')))
    
    enrichi = [r for r in results if r is not None]
    df_enrichi = pd.DataFrame(enrichi)
    df_enrichi.to_csv('df_enrichi.csv', index=False, encoding='utf-8')
    print(f"▶ {len(df_enrichi)} Enrichissements terminés.")
    return df_enrichi


def mitre(cve_id):
    url = ENRICH_PATHS["mitre"]+cve_id
    response = requests.get(url)
    data = response.json()
    # Extraire la description
    cna = data.get("containers", {}).get("cna", {})
    descriptions = cna.get("descriptions", [])
    description = descriptions[0].get("value") if descriptions else "Non disponible"
    # Extraire le score CVSS
    #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
    #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
    cvss_score = "Non disponible"
    attack_vector = "Non disponible"
    integrity_impact = "Non disponible"
    user_interaction = "Non disponible"
    attack_complexity = "Non disponible"
    availability_impact = "Non disponible"
    privileges_required = "Non disponible"
    confidentiality_impact = "Non disponible"
    metrics = cna.get("metrics", [])
    if metrics:
        cvss_data = next(
            (v for k, v in metrics[0].items() if k.startswith("cvssV") and isinstance(v, dict)),
            None
        )
        if cvss_data:
            cvss_score = cvss_data.get("baseScore", "Non disponible")
            attack_vector = cvss_data.get("attackVector", "Non disponible")
            integrity_impact = cvss_data.get("integrityImpact", "Non disponible")
            user_interaction = cvss_data.get("userInteraction", "Non disponible")
            attack_complexity = cvss_data.get("attackComplexity", "Non disponible")
            availability_impact = cvss_data.get("availabilityImpact", "Non disponible")
            privileges_required = cvss_data.get("privilegesRequired", "Non disponible")
            confidentiality_impact = cvss_data.get("confidentialityImpact", "Non disponible")
            
    cwe = "Non disponible"
    cwe_desc = "Non disponible"
    problemtype = cna.get("problemTypes", [])
    if problemtype:
        descriptions = problemtype[0].get("descriptions", [])
        if descriptions:
            cwe = descriptions[0].get("cweId", "Non disponible")
            cwe_desc = descriptions[0].get("description", "Non disponible")
    # Extraire les produits affectés
    affected = cna.get("affected", [])
    if affected:
        for product in affected:
            vendor = product.get("vendor", "Inconnu")
            product_name = product.get("product") or product.get("packageName", "Inconnu")
            versions = [
                v.get("version", "unknown")
                for v in product.get("versions", [])
                if v.get("status") == "affected"
            ]
            print(f"▶ Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
    # Afficher les résultats
    print(f"▶ CVE : {cve_id}")
    print(f"▶ Description : {description}")
    print(f"▶ Score CVSS : {cvss_score}")
    print(f"▶ Type CWE : {cwe}")
    print(f"▶ CWE Description : {cwe_desc}")
    return [affected,description,cvss_score,cwe,cwe_desc,attack_vector,integrity_impact,user_interaction,attack_complexity,availability_impact,privileges_required,confidentiality_impact]

def first(cve_id):
    url = ENRICH_PATHS["first"]+cve_id
    # Requête GET pour récupérer les données JSON
    response = requests.get(url)
    data = response.json()
    # Extraire le score EPSS
    epss_data = data.get("data", [])
    if epss_data:
        epss_score = epss_data[0]["epss"]
        print(f"▶ CVE : {cve_id}")
        print(f"▶ Score EPSS : {epss_score}")
        return epss_score
    else:
        print(f"▶ Aucun score EPSS trouvé pour {cve_id}")
    return -1

def consolider(df_bulletins, df_enrichi):
    dico_consolider = []
    bulletins_dict = df_bulletins.set_index("ID ANSSI").to_dict(orient="index")
    for enrichi_index, enrichi_ligne in df_enrichi.iterrows():
        mitre = enrichi_ligne.get("Mitre", [])
        if not isinstance(mitre, (list, tuple)):
            mitre = []

        affected = mitre[0] if len(mitre) > 0 else []
        description = mitre[1] if len(mitre) > 1 else "Non disponible"
        cvss = mitre[2] if len(mitre) > 2 else "Non disponible"
        cwe = mitre[3] if len(mitre) > 3 else "Non disponible"
        attack_vector = mitre[5] if len(mitre) > 5 else "Non disponible"
        integrity_impact = mitre[6] if len(mitre) > 6 else "Non disponible"
        user_interaction = mitre[7] if len(mitre) > 7 else "Non disponible"
        attack_complexity = mitre[8] if len(mitre) > 8 else "Non disponible"
        availability_impact = mitre[9] if len(mitre) > 9 else "Non disponible"
        privileges_required = mitre[10] if len(mitre) > 10 else "Non disponible"
        confidentiality_impact = mitre[11] if len(mitre) > 11 else "Non disponible"

        bulletin_info = bulletins_dict.get(enrichi_ligne["ID ANSSI"], {})        
        titre = bulletin_info.get("Titre", "Non disponible")
        type_ = bulletin_info.get("Type", "Non disponible")
        date = bulletin_info.get("Date", "Non disponible")
        lien = bulletin_info.get("Lien", "Non disponible")
        
        if affected:
            for product in affected:
                ligne = {
                    "ID ANSSI": enrichi_ligne["ID ANSSI"],
                    "Titre ANSSI": titre,
                    "Type": type_,
                    "Date": date,
                    "CVE": enrichi_ligne.get("CVE", "Non disponible"),
                    "CVSS": cvss,
                    "Base Severity": calcul_severity(cvss),
                    "CWE": cwe,
                    "EPSS": enrichi_ligne.get("EPSS", "Non disponible"),
                    "Lien": lien,
                    "Description": description,
                    "Éditeur": product.get("vendor", "Inconnu"),
                    "Produit": product.get("product") or product.get("packageName", "Inconnu"),
                    "Versions affectées": [v.get("version", "unknown") for v in product.get("versions", []) if v.get("status") == "affected"],
                    "Attack Vector": attack_vector,
                    "Integrity Impact": integrity_impact,
                    "User Interaction": user_interaction,
                    "Attack Complexity": attack_complexity,
                    "Availability Impact": availability_impact,
                    "Privileges Required": privileges_required,
                    "Confidentiality Impact": confidentiality_impact,
                }
                dico_consolider.append(ligne)
        else:
            ligne = {
                "ID ANSSI": enrichi_ligne["ID ANSSI"],
                "Titre ANSSI": titre,
                "Type": type_,
                "Date": date,
                "CVE": enrichi_ligne.get("CVE", "Non disponible"),
                "CVSS": cvss,
                "Base Severity": calcul_severity(cvss),
                "CWE": cwe,
                "EPSS": enrichi_ligne.get("EPSS", "Non disponible"),
                "Lien": lien,
                "Description": description,
                "Éditeur": "Non disponible",
                "Produit": "Non disponible",
                "Versions affectées": "Non disponible",
                "Attack Vector": attack_vector,
                "Integrity Impact": integrity_impact,
                "User Interaction": user_interaction,
                "Attack Complexity": attack_complexity,
                "Availability Impact": availability_impact,
                "Privileges Required": privileges_required,
                "Confidentiality Impact": confidentiality_impact,
            }
            dico_consolider.append(ligne)

    df_consolider = pd.DataFrame(dico_consolider)
    df_consolider.to_csv('df_consolider.csv', index=False, encoding='utf-8')
    print(f"▶ {len(df_consolider)} consolidations des données terminées.")
    return df_consolider

def calcul_severity(s):
    try:
        score = float(s)
    except (ValueError, TypeError):
        return "Non disponible"
    
    if score < 4:
        return "Faible"
    elif score < 7:
        return "Moyenne"
    elif score < 9:
        return "Élevée"
    else:
        return "Critique"

def visualisation(df_final):
    df = df_final.copy()
    df["Score CVSS"] = pd.to_numeric(df["CVSS"], errors="coerce")
    df["Score EPSS"] = pd.to_numeric(df["EPSS"], errors="coerce")
    df["Date"] = pd.to_datetime(df["Date"], format='%a, %d %b %Y %H:%M:%S %z', errors='coerce')

    sns.set(style="whitegrid")
    
    plt.figure(figsize=(10, 6))
    plt.title("Histogramme des scores CVSS")
    sns.histplot(df["Base Severity"], bins=10, kde=True, color="skyblue")
    plt.xlabel("Score CVSS")
    plt.ylabel("Nombre de vulnérabilités")
    plt.tight_layout()
    plt.show()
    
    plt.figure(figsize=(12, 6))
    top_cwe = df["CWE"].value_counts().head(10)
    top_cwe.plot.pie(autopct='%1.1f%%', startangle=140, figsize=(8, 8), title="Top 10 des types CWE")
    plt.ylabel("")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(10, 6))
    sns.kdeplot(df["Score EPSS"].dropna(), fill=True, color="salmon")
    plt.title("Courbe des scores EPSS")
    plt.xlabel("Score EPSS")
    plt.tight_layout()
    plt.show()

    top_vendors = df["Éditeur"].value_counts().head(10)
    plt.figure(figsize=(12, 6))
    sns.barplot(x=top_vendors.values, y=top_vendors.index, palette="Blues_r")
    plt.title("Classement des éditeurs les plus affectés ")
    plt.xlabel("Nombre de vulnérabilités")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(6, 5))
    corr = df[["Score CVSS", "Score EPSS"]].dropna().corr()
    sns.heatmap(corr, annot=True, cmap="coolwarm", center=0)
    plt.title("Heatmap des corrélations entre CVSS et EPSS")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(10, 6))
    sns.scatterplot(data=df, x="Score CVSS", y="Score EPSS", hue="Base Severity", palette="Set2", alpha=0.7)
    plt.title("Nuage de points entre Score CVSS et Score EPSS")
    plt.xlabel("Score CVSS")
    plt.ylabel("Score EPSS")
    plt.legend(title="Gravité")
    plt.tight_layout()
    plt.show()

    df_temps = df.dropna(subset=["Date"])
    df_temps = df_temps.sort_values("Date")
    df_temps["Cumul"] = range(1, len(df_temps) + 1)
    plt.figure(figsize=(10, 6))
    plt.plot(df_temps["Date"], df_temps["Cumul"], color="green")
    plt.title("Courbe cumulative des vulnérabilités en fonction du temps")
    plt.xlabel("Date")
    plt.ylabel("Nombre cumulé")
    plt.tight_layout()
    plt.show()

    top_vendors = df["Éditeur"].value_counts().head(5).index
    df_box = df[df["Éditeur"].isin(top_vendors)]
    plt.figure(figsize=(12, 6))
    sns.boxplot(data=df_box, x="Éditeur", y="Score CVSS", palette="Pastel1")
    plt.title("Boxplot des scores CVSS par éditeur ")
    plt.tight_layout()
    plt.show()
    
    cwe_counts = df["CWE"].value_counts().head(10)
    top_cwes = cwe_counts.index[1:4]

    plt.figure(figsize=(10, 6))
    for cwe in top_cwes:
        df_cwe = df[df["CWE"] == cwe].dropna(subset=["Date"])
        df_cwe["Année"] = df_cwe["Date"].dt.year
        cwe_by_year = df_cwe["Année"].value_counts().sort_index()
        sns.lineplot(x=cwe_by_year.index, y=cwe_by_year.values, label=cwe)

    plt.title("Évolution temporelle des vulnérabilités pour les CWE (rangs 2 à 4)")
    plt.xlabel("Année")
    plt.ylabel("Nombre de vulnérabilités")
    plt.legend(title="CWE")
    plt.tight_layout()
    plt.show()

    df_bulletin = df[df["Type"].isin(["alerte", "avis"])]
    top_editeurs = df_bulletin["Éditeur"].value_counts().head(10)
    df_bulletin = df_bulletin[df_bulletin["Éditeur"].isin(top_editeurs)]
    plt.figure(figsize=(12, 6))
    sns.countplot(data=df_bulletin, y="Éditeur", hue="Type", palette="Set2")
    plt.title("Nombre de vulnérabilités par éditeur selon le type de bulletin")
    plt.xlabel("Nombre de vulnérabilités")
    plt.ylabel("Éditeur")
    plt.legend(title="Type")
    plt.tight_layout()
    plt.show()
    
    print("▶ Visualisations générées avec succès.")

def KM():
    # Chargement
    df = pd.read_csv("df_consolider.csv")
    
    # On garde les colonnes importantes
    cols_categorique = [
        "Base Severity",
        "Attack Vector",
        "Integrity Impact",
        "User Interaction",
        "Attack Complexity",
        "Availability Impact",
        "Privileges Required",
        "Confidentiality Impact"
    ]
    for col in ["CVSS", "EPSS"]:
        df[col] = df[col].replace("Non disponible", np.nan)
        df[col] = pd.to_numeric(df[col], errors='coerce')
    # Nettoyage : enlever lignes avec valeurs manquantes dans ces colonnes
    df_clean = df.dropna(subset=["CVSS", "EPSS"] + cols_categorique)
    
    # Encoder les colonnes catégorielles
    for col in cols_categorique:
        le = LabelEncoder()
        df_clean[col] = le.fit_transform(df_clean[col].astype(str))
    
    # Extraction des features
    X = df_clean[["CVSS", "EPSS"] + cols_categorique] 
    
    # Standardisation
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Clustering KMeans
    kmeans = KMeans(n_clusters=5, random_state=42)
    clusters = kmeans.fit_predict(X_scaled)
    df_clean["Cluster"] = clusters
    
    #Silhouette score
    silhouette = silhouette_score(X_scaled, clusters)
    print(f"▶ Silhouette score : {silhouette:.3f} (proche de 1 = bon)")
    
    # Visualisation PCA
    pca = PCA(n_components=2, random_state=42)
    X_pca = pca.fit_transform(X_scaled)
    
    plt.figure(figsize=(10, 6))
    sns.scatterplot(x=X_pca[:, 0], y=X_pca[:, 1], hue=df_clean["Cluster"], palette="Set2")
    plt.title("KMeans des vulnérabilités (PCA)")
    plt.xlabel("PC1")
    plt.ylabel("PC2")
    plt.grid()
    plt.show()
    
    # Afficher quelques stats descriptives par cluster
    print("▶ Moyennes par cluster :",df_clean.groupby("Cluster")[["CVSS", "EPSS"] + cols_categorique].mean())
    
    # Inverse la standardisation pour les centres
    centers = scaler.inverse_transform(kmeans.cluster_centers_)
    centers_df = pd.DataFrame(centers, columns=X.columns)
    print("▶ Centres des clusters:",centers_df)
    
    # Statistiques descriptives par cluster
    stats_par_cluster = df_clean.groupby("Cluster")[["CVSS", "EPSS", "Base Severity"]].agg([np.mean, np.median, np.std])
    print("▶ Statistiques descriptives par cluster :",stats_par_cluster)
    
def RandomForest():
    df = pd.read_csv("df_consolider.csv")
    features = [
        'Attack Vector', 'Integrity Impact',
        'Attack Complexity', 'Availability Impact', 'Privileges Required', 'Confidentiality Impact'
    ]
    # Remplacer les "Non disponible" par np.nan et supprimer les lignes avec EPSS manquant
    df_filtered = df[df['EPSS'] != 'Non disponible'].copy()
    df_filtered['EPSS'] = df_filtered['EPSS'].astype(float)
    
    # Créer la variable cible binaire : EPSS élevé ou non
    df_filtered['EPSS_elevé'] = df_filtered['EPSS'].apply(lambda x: 1 if x >= 0.7 else 0)
    # Encodage des variables catégorielles
    X = df_filtered[features].apply(LabelEncoder().fit_transform)
    y = df_filtered['EPSS_elevé']
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
    
    # Modèle
    rf = RandomForestClassifier(random_state=42)
    rf.fit(X_train, y_train)
    
    # Prédictions
    y_pred = rf.predict(X_test)
    
    # Rapport
    print("Rapport de classification :")
    print(classification_report(y_test, y_pred))
    
    #Matrice de confusion
    cm = confusion_matrix(y_test, y_pred)
    ConfusionMatrixDisplay(cm).plot()
    plt.title("Matrice de confusion")
    plt.show()
    
    #ROC Curve et AUC
    y_proba = rf.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc = roc_auc_score(y_test, y_proba)
    
    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC = {auc:.2f}")
    plt.plot([0, 1], [0, 1], '--', color='gray')
    plt.title("Courbe ROC")
    plt.xlabel("Taux de faux positifs")
    plt.ylabel("Taux de vrais positifs")
    plt.legend()
    plt.grid()
    plt.show()
    
    # Validation croisée
    scores = cross_val_score(rf, X, y, cv=5)
    print(f"Accuracy moyenne : {scores.mean()}")
    importances = rf.feature_importances_
    indices = np.argsort(importances)[::-1]
    plt.figure(figsize=(8, 4))
    plt.title("Importance des variables")
    plt.bar(range(X.shape[1]), importances[indices])
    plt.xticks(range(X.shape[1]), [features[i] for i in indices], rotation=45)
    plt.tight_layout()
    plt.show()
    
def envoyer_email(destinataire, sujet, corps, config_smtp):
    msg = MIMEText(corps)
    msg['From'] = config_smtp['user']
    msg['To'] = destinataire
    msg['Subject'] = sujet
    serveur = smtplib.SMTP(config_smtp['server'], config_smtp['port'])
    serveur.starttls()
    serveur.login(config_smtp['user'], config_smtp['password'])
    serveur.send_message(msg)
    serveur.quit()
    print(f"▶ Email envoyé à {destinataire}.")
    
def main():
    start = time.time()
    df_bul = charger_flux_rss()
    df_cve = extraire_cve(df_bul)
    df_enrichi = enrichir_cve(df_cve)
    df_final = consolider(df_bul, df_enrichi)
    visualisation(df_final)
    RandomForest()
    KM()
    config_smtp = {
        'server': 'smtp.gmail.com',
        'port': 587,
        'user': "mymail@mail.com",
        'password': "mdp"
    }
    destinataire = "mail@mail.com"
    df_final['CVSS'] = pd.to_numeric(df_final['CVSS'], errors='coerce')
    critique = df_final[df_final['CVSS'] >= 9]
    for idx, row in critique.iterrows():
        produit = row.get('produits', 'Produit inconnu')
        cve_id = row.get('CVE', 'CVE inconnu')
        cvss = row.get('CVSS', 'N/A')
        description = row.get('description', 'Pas de description')
        
        sujet = f"[ALERTE CRITIQUE] Vulnérabilité {cve_id} détectée"
        corps = f"""▶ Alerte ◀ 
        Vulnérabilité {cve_id} détectée
        Une vulnérabilité critique avec un CVSS de {cvss} a été détectée.
            ▶ ID de la vulnérabilité: {cve_id}
            ▶ Produit: {produit}
            ▶ Description: {description}
        """
        envoyer_email(destinataire, sujet, corps, config_smtp)
    print(f"Temps de chargement: {time.time() - start:.2f} s")

if __name__ == "__main__":
    main()
