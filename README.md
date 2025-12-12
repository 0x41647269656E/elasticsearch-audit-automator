# elasticsearch-audit-automator

Un outil en Python pour automatiser l’audit de clusters Elasticsearch via HTTP(S) ou rebond SSH. Il exécute une liste de commandes définies dans `commands.json`, stocke chaque résultat dans un dossier d’audit horodaté, consigne les erreurs et prépare un contexte pour un futur script d’analyse.

## Fonctionnalités
- Connexion directe HTTP/HTTPS ou via rebond SSH (Paramiko).
- Authentification basique ou Bearer Token.
- Chargement de la configuration depuis `.env` avec surcharge par arguments CLI.
- Exécution séquentielle des commandes définies dans `commands.json` (version 1.0).
- Sauvegarde des réponses en JSON ou texte selon `output_format`.
- Journalisation des commandes en échec dans `errors.log`.
- Génération d’un fichier `audit_infos.json` résumant la session (méthode de connexion, commandes exécutées/échouées, infos des nœuds, etc.).
- Invitation à lancer ultérieurement `analyse.py` en pointant vers le dossier d’audit.

## Installation
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # voir dépendances ci-dessous si vous préférez installer manuellement
```

Dépendances clés :
- `requests`
- `paramiko`
- `python-dotenv`

## Configuration
1. Copiez `.env.example` en `.env` et ajustez les valeurs :
```bash
cp .env.example .env
```

Variables principales :
- `ELASTIC_HOST` / `ELASTIC_PORT` / `ELASTIC_SCHEME` : cible Elasticsearch.
- `ELASTIC_USERNAME` / `ELASTIC_PASSWORD` ou `ELASTIC_BEARER_TOKEN` : authentification.
- `VERIFY_TLS` : `true`/`false` pour la validation TLS.
- `CLIENT_NAME` / `CLUSTER_NAME` : noms utilisés dans les dossiers d’audit.
- `SSH_HOST`, `SSH_PORT`, `SSH_USERNAME`, `SSH_KEY_PATH`, `SSH_PASSWORD` : remplissez si vous passez par un rebond SSH.

Les arguments CLI surchargent les valeurs du fichier `.env`.

## commands.json
Le fichier doit respecter le format suivant (version 1.0) :
```json
{
  "version": "1.0",
  "commands": [
    {
      "name": "command-name",
      "description": "Description de la commande",
      "command": "GET /_cluster/health",
      "prompt": "Prompt pour l'analyse future",
      "output_format": "json"
    }
  ]
}
```

Exemples fournis : état du cluster, statistiques des nœuds, paramètres dynamiques, liste des index et licence.

## Lancer un audit
```bash
python main.py \
  --host 10.0.0.5 \
  --scheme https \
  --username elastic \
  --password "changeme" \
  --client-name acme
```

Pour utiliser un rebond SSH :
```bash
python main.py \
  --ssh-host jump.acme.local \
  --ssh-username audit \
  --ssh-key-path ~/.ssh/id_rsa \
  --host 172.20.10.15 \
  --port 9200
```

Chaque audit crée un dossier `data/YYYY-MM-DD_HH-mm-ss-<client>-<cluster>` contenant les réponses aux commandes, `audit_infos.json` et éventuellement `errors.log`.

## Provisionner des clusters de test (Docker Compose)
### Prérequis
- Docker et Docker Compose
- Environ 8 Go de RAM libre (3 nœuds Elasticsearch + service de chargement de données)

### Cluster Elasticsearch 7.17 (HTTP, basic auth)
Un jeu de conteneurs Docker permet de démarrer trois nœuds 7.17.22 avec sécurité activée et un utilisateur `audit-elasticsearch`/`audit-me` créé automatiquement par le service `data-loader` après vérification que le cluster est `green`.

Commandes :
```bash
docker compose -f test/7.17/docker-compose.yml up -d
# Surveillez les logs si besoin
docker compose -f test/7.17/docker-compose.yml logs -f data-loader
```

Paramètres clés :
- Accès HTTP : `http://localhost:9200`
- Superuser initial : `elastic` / `changeme`
- Utilisateur d’audit : `audit-elasticsearch` / `audit-me`
- Indices générés automatiquement : `audit-demo-7-01` à `audit-demo-7-10`
- Jeux de données (~500 Mo) tirés des dumps publics GitHub Archive (`DATASET_URLS` dans le compose)

### Cluster Elasticsearch 8.x (HTTPS avec certificats)
La pile 8.12.2 démarre avec TLS activé. Un conteneur `certgen` génère une AC et un certificat serveur partagés placés dans `test/certs` (déjà pré-générés dans le dépôt et régénérables via `test/8/generate-certs.sh`).

Commandes :
```bash
# Facultatif : régénérer les certificats
CERTS_DIR=$(pwd)/test/certs sh test/8/generate-certs.sh

docker compose -f test/8/docker-compose.yml up -d
docker compose -f test/8/docker-compose.yml logs -f data-loader
```

Paramètres clés :
- Accès HTTPS : `https://localhost:9300`
- AC et certificats : `test/certs/ca.crt`, `test/certs/tls.crt`, `test/certs/tls.key`
- Superuser initial : `elastic` / `changeme`
- Utilisateur d’audit : `audit-elasticsearch` / `audit-me`
- Indices générés automatiquement : `audit-demo-8-01` à `audit-demo-8-10`

Le service `data-loader` vérifie la santé du cluster, attend l’état `green`, crée l’utilisateur cible si besoin, provisionne 10 indices et charge plusieurs fichiers JSON publics (~500 Mo) en bulk.

### Utiliser `main.py` contre les clusters de test
#### Mode HTTP (cluster 7.17)
```bash
python main.py \
  --host localhost \
  --port 9200 \
  --scheme http \
  --username audit-elasticsearch \
  --password audit-me \
  --client-name local-lab \
  --cluster-name audit-es7
```

#### Mode HTTPS (cluster 8.x)
```bash
python main.py \
  --host localhost \
  --port 9300 \
  --scheme https \
  --username audit-elasticsearch \
  --password audit-me \
  --verify-tls true \
  --ca-cert test/certs/ca.crt \
  --client-name local-lab \
  --cluster-name audit-es8
```

Adaptez les chemins/ports si vous exécutez Docker sur une machine distante. Les paramètres `.env` peuvent également refléter ces valeurs (les arguments CLI prennent le pas sur le fichier).

## Ajouter de nouvelles commandes
1. Éditez `commands.json` et ajoutez une entrée dans `commands` en respectant le schéma.
2. Fixez `output_format` à `json` (réponse parsée et indentée) ou `text`.
3. Enregistrez et relancez `main.py`.

## Exemple d’exécution
```bash
python main.py --commands commands.json
Executing cluster-health: GET /_cluster/health
Executing nodes-stats: GET /_nodes/stats
Executing cluster-settings: GET /_cluster/settings?include_defaults=true
Executing indices-overview: GET /_cat/indices?format=json&bytes=b
Executing license: GET /_license
Analyse ignorée. Les données d'audit sont prêtes.
```

Le script propose ensuite : `Souhaitez-vous lancer le script d’analyse ? (Y/n)`. Répondez `Y` pour exécuter `analyse.py` en lui passant le chemin du dossier d’audit généré.

## Licence
Ce projet est distribué sous licence MIT. Voir le fichier [LICENSE](LICENSE).
