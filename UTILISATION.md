# Guide d'utilisation

Le projet se déroule en **deux temps distincts**, et c'est le point qui déroute
le plus au début :

| | Rôle | Ce dont il a besoin | Ce qu'il produit |
|---|---|---|---|
| `main.py` | **collecte** | identifiants du cluster | un dossier `data/<horodatage>-<client>-<cluster>/` |
| `analyse.py` | **analyse** | un dossier déjà collecté + une clé Anthropic | `rapport.md`, `constats.json`, `consommation.json` |

`analyse.py` **ne se connecte jamais à Elasticsearch**. Inutile donc de lui
passer un hôte ou un mot de passe : le dossier contient déjà tout.

## Mise en route

```bash
python -m venv .venv
.venv/Scripts/Activate.ps1          # PowerShell ; sur Unix : source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                # puis remplacer les valeurs
```

## Enchaînement standard

```bash
# 1. Collecte — interroge le cluster, n'analyse rien
python main.py --host es.exemple.local --port 9200 --scheme https \
    --username audit-elasticsearch --password '…' \
    --ca-cert /chemin/ca.crt \
    --client-name acme --cluster-typology PRODUCTION

# 2. Analyse — relit le dossier produit, appelle le modèle
python analyse.py data/2026-08-01_11-30-31-acme-audit-es8 --effort high
```

À la fin de la collecte, `main.py` propose de lancer l'analyse directement ;
répondre `Y` revient à exécuter la seconde commande.

## Variables `.env`

Tout ce qui suit se passe aussi en argument de ligne de commande, **qui l'emporte
sur le fichier**. Voir `.env.example` pour le fichier commenté.

| Variable | Rôle |
|---|---|
| `ELASTIC_HOST`, `ELASTIC_PORT`, `ELASTIC_SCHEME` | cible de la collecte |
| `ELASTIC_USERNAME`, `ELASTIC_PASSWORD` | authentification basique |
| `ELASTIC_BEARER_TOKEN` | alternative au mot de passe |
| `VERIFY_TLS` | `false` uniquement en laboratoire |
| `CA_CERT_PATH` | autorité de certification du cluster |
| `CLIENT_NAME` | nom repris dans le dossier d'audit |
| `CLUSTER_TYPOLOGY` | `PRODUCTION`, `PREPROD`, `RECETTE`, `DEV`, `AUTRE` |
| `REQUEST_TIMEOUT` | délai par requête, en secondes |
| `ANTHROPIC_API_KEY` | clé pour l'analyse, créée sur <https://platform.claude.com> |
| `SSH_*` | rebond, uniquement si le cluster n'est pas joignable directement |

**`CLUSTER_TYPOLOGY` n'est pas décoratif** : il pondère la sévérité de chaque
constat. Un index sans replica est `CRITIQUE` en `PRODUCTION` et `INFORMATIF` en
`DEV`. Le renseigner de travers fausse tout le rapport.

Les variables des conteneurs de test (`TARGET_USERNAME`, `INDEX_COUNT`,
`WORKER_OPS`…) ne se mettent **pas** dans `.env` : elles vivent dans les
`test/*/docker-compose.yml`.

## Options de `main.py`

| Option | Effet |
|---|---|
| `--host`, `--port`, `--scheme` | cible ; `scheme` vaut `http` ou `https` |
| `--username`, `--password`, `--token` | authentification |
| `--ca-cert` | autorité de certification |
| `--verify-tls {true,false}` | validation du certificat |
| `--client-name` | nom du client dans le dossier d'audit |
| `--cluster-typology` | `PRODUCTION`, `PREPROD`, `RECETTE`, `DEV`, `AUTRE` |
| `--timeout` | délai par requête, en secondes (défaut 60) |
| `--commands` | autre fichier que `commands.json` |
| `--ssh-host`, `--ssh-port`, `--ssh-username`, `--ssh-password`, `--ssh-key-path` | rebond SSH |

## Options de `analyse.py`

| Option | Effet |
|---|---|
| `--effort {low,medium,high,xhigh,max}` | profondeur de raisonnement, défaut `high` — **principal levier de coût** |
| `--model` | modèle à utiliser, défaut `claude-opus-5` |
| `--axe <clé>` | rejoue un seul axe, à côté du rapport complet sans l'écraser |
| `--rerender [fichier]` | régénère le Markdown depuis `constats.json`, **sans aucun appel ni dépense** |
| `--dry-run` | produit la structure du rapport sans appeler le modèle |
| `--no-check-refs` | n'interroge pas les URL citées pour vérifier qu'elles résolvent |
| `--no-fallback` | désactive le repli serveur en cas de refus du modèle |
| `--budget-tokens` | seuil au-delà duquel les artefacts d'un axe sont agrégés |

Les clés d'axe sont celles de `commands.json` : `resilience`,
`dimensionnement`, `shards`, `indexation`, `recherche`, `disque`,
`cycle_de_vie`, `sauvegarde`, `securite`, `licence`.

## Situations courantes

**Valider la forme du rapport sans rien dépenser**

```bash
python analyse.py data/<dossier> --dry-run
```

**Rejouer un seul axe après avoir ajusté son prompt**

```bash
python analyse.py data/<dossier> --axe securite --effort xhigh
```

Produit `rapport-rejeu-securite-<horodatage>.md` et ses deux compagnons. Le
rapport complet n'est pas touché, et deux rejeux successifs coexistent.

**Corriger la mise en forme sans repayer l'analyse**

```bash
python analyse.py data/<dossier> --rerender
```

Reconstruit le Markdown depuis `constats.json`. Aucun appel au modèle.

**Auditer les stacks de test locales**

```bash
docker compose -p es8 -f test/8.19.9/docker-compose.yml up -d
python main.py --host localhost --port 9300 --scheme https \
    --username audit-elasticsearch --password audit-me \
    --ca-cert test/8.19.9/certs/ca/ca.crt \
    --client-name lab --cluster-typology RECETTE
```

Ports par version — une seule stack à la fois, chacune réclame environ 4,5 Go :

| Version | Schéma | es01 / es02 / es03 | Kibana |
|---|---|---|---|
| 7.17.29 | http | 9200 / 9201 / 9202 | 5601 |
| 8.19.9 | https | 9300 / 9301 / 9302 | 5602 |
| 9.2.3 | https | 9400 / 9401 / 9402 | 5603 |
| 9.4.4 | https | 9500 / 9501 / 9502 | 5604 |

## Coût

Le coût suit **le nombre d'index, de shards, de segments et de champs de
mapping** — ni le volume de données ni le nombre de documents, qui ne changent
que des valeurs numériques dans le JSON, pas sa taille.

L'entrée est incompressible et indépendante de l'effort ; `--effort` n'agit que
sur la sortie, raisonnement compris. Sur un cluster de 400 index, comptez 50 à
100 € ; sur une stack de test, quelques dollars.

`consommation.json` donne le coût **mesuré** après chaque analyse, par axe et au
total. Pour estimer avant de lancer, `--dry-run` valide la forme sans dépenser.

## Fichiers produits

| Fichier | Contenu |
|---|---|
| `rapport.md` | le compte-rendu : blocs de commande, constats, angles morts |
| `constats.json` | les constats structurés — permet `--rerender` |
| `consommation.json` | jetons et coût réels, par axe |
| `<commande>.json` / `.txt` | les relevés bruts, livrés tels quels au client |
| `audit_infos.json` | contexte : cluster, typologie, nœud, commandes en échec |
| `errors.log` | commandes ayant échoué, avec leur message |

Le rapport ne recopie pas les relevés bruts : ils sont livrés en fichiers à côté.
Le Markdown reste donc lisible quelle que soit la taille du cluster.

## Deux garanties du rapport

**Les commandes en échec sont déclarées.** Un axe dont les commandes ont été
refusées annonce son angle mort au lieu de conclure à l'absence de problème.

**Les citations sont revérifiées.** Chaque extrait sur lequel repose un constat
est recherché dans l'artefact d'origine, et les URL citées sont interrogées. Un
fragment introuvable ou un lien mort est signalé comme tel plutôt que présenté
comme une preuve.
