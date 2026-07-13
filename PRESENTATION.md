# ÉON — Documentation technique pour la présentation

> Outil web d'audit de sécurité pour TPE/PME. On saisit un nom de domaine, ÉON exécute
> 7 modules d'analyse **passive** (aucune attaque, 100 % légal), calcule un score global
> sur 100, génère un rapport PDF et propose un assistant IA pour expliquer les résultats.
>
> Démo live : http://132.145.74.215

---

## 1. Vue d'ensemble de l'architecture

```
┌─────────────────────┐         ┌──────────────────────────────────────┐
│      FRONTEND       │         │              BACKEND                 │
│  SPA HTML/CSS/JS    │  HTTP   │           FastAPI (Python)           │
│  vanilla (app.js)   │────────▶│                                      │
│                     │  SSE    │  /api/v1/scan/stream  ← scan live    │
│  servi par nginx    │◀────────│  /api/v1/scan/{id}/pdf ← rapport     │
│  (prod) ou file://  │         │  /api/v1/chat/{id}     ← IA          │
└─────────────────────┘         └──────┬───────────┬─────────┬─────────┘
                                       │           │         │
                                ┌──────▼─────┐ ┌───▼────┐ ┌──▼───────────┐
                                │ 7 analyzers│ │ SQLite │ │ API externes │
                                │ (modules)  │ │ eon.db │ │ HIBP, URLhaus│
                                └────────────┘ └────────┘ │ WHOIS, DNS   │
                                                          │ Claude (IA)  │
                                                          └──────────────┘
```

**Stack technique :**

| Couche | Technologie | Rôle |
|---|---|---|
| Frontend | HTML/CSS/JS vanilla (pas de framework) | SPA à 3 pages : formulaire → chargement → résultats |
| Backend | FastAPI + Uvicorn (Python 3.11) | API REST + streaming SSE |
| Validation | Pydantic v2 | Modèles typés, validation du domaine en entrée |
| Base de données | SQLite + SQLAlchemy (ORM) | Persistance des scans et des résultats de modules |
| PDF | Jinja2 + WeasyPrint | Template HTML → rendu PDF |
| IA | API Anthropic (Claude Haiku) | Chatbot contextualisé sur les résultats du scan |
| Déploiement | Docker (backend) + nginx (frontend) sur VPS Oracle Cloud | Production |

**Arborescence :**

```
backend/
├── main.py                  # Point d'entrée FastAPI (app, CORS, lifespan)
├── config.py                # Settings (pydantic-settings, lit le .env)
├── database.py              # Engine SQLAlchemy + session
├── db_models.py             # Tables ORM : scans, modules
├── pdf_report.py            # Génération du rapport PDF
├── api/
│   ├── routes.py            # Endpoints de scan (POST /scan, /scan/stream, GET pdf…)
│   ├── chat.py              # Endpoint du chatbot IA
│   └── models.py            # Modèles Pydantic (ScanRequest, ScanResult…)
├── analyzers/               # Les 7 modules + détection de plateforme
├── templates/report.html.j2 # Template Jinja2 du PDF
└── tests/                   # Tests unitaires (mocks) + intégration
frontend/
├── index.html               # Coquille vide (<div id="app">)
├── app.js                   # Toute la logique SPA (~580 lignes)
└── styles.css
```

---

## 2. Cycle de vie d'un scan (le flux principal)

C'est **LE** parcours à raconter en présentation :

1. **L'utilisateur saisit un domaine** dans le frontend (`buildScan()` dans `app.js`).
2. Le frontend envoie `POST /api/v1/scan/stream` avec `{"domain": "exemple.com"}`.
3. **Validation Pydantic** (`api/models.py`, `ScanRequest`) :
   - nettoyage (`https://`, `www.`, minuscules) ;
   - regex de format de domaine ;
   - **résolution DNS réelle** (enregistrement A, sinon MX) — un domaine inexistant est rejeté avant tout scan.
4. Le backend vérifie une dernière fois que le domaine résout (`socket.getaddrinfo`), génère un
   `scan_id` (UUID v4), puis détecte la **plateforme** (Shopify/Wix/WordPress/custom).
5. Les **7 modules s'exécutent séquentiellement**. Avant chaque module, le serveur pousse un
   événement **SSE** (Server-Sent Events) :
   ```
   data: {"step": "DNS Security", "progress": 0, "total": 7}
   ```
   → le frontend met à jour la barre de progression **en temps réel**.
   Chaque module est une fonction synchrone (I/O réseau bloquant), exécutée via
   `run_in_threadpool` pour ne pas bloquer la boucle asyncio de FastAPI.
6. **Score global** = moyenne des 7 scores de modules (`sum // 7`).
7. Le résultat complet est **persisté en base** (table `scans` + table `modules`, relation 1-N
   avec cascade delete), puis envoyé au frontend dans un dernier événement SSE
   `{"done": true, "scan_id": …, "result": {…}}`.
8. Le frontend affiche la page résultats : score, cartes par module (dépliables avec détails +
   recommandations), plan d'actions priorisé par sévérité, bouton PDF, chatbot IA.

> Il existe aussi un endpoint `POST /scan` classique (sans streaming) qui fait la même chose
> d'un bloc — utile pour les tests et l'API pure.

### Pourquoi SSE et pas WebSocket ?
Le flux est **unidirectionnel** (serveur → client) : SSE suffit, c'est du simple HTTP
(`text/event-stream`), plus léger à implémenter et compatible avec `fetch` + `ReadableStream`
côté navigateur. Le header `X-Accel-Buffering: no` empêche nginx de mettre le flux en tampon.

---

## 3. Le système de scoring (commun à tous les modules)

Chaque module retourne un objet `ModuleResult` :

```python
ModuleResult(
    module_name="DNS Security",
    status="success" | "warning" | "error",
    severity=CRITICAL | HIGH | MEDIUM | LOW | INFO,
    score=0..100,                    # points gagnés selon les vérifications
    details={...},                   # données brutes affichées dans l'UI/PDF
    recommendations=[...],           # conseils rédigés pour un non-technicien
)
```

La plupart des modules **additionnent des points** par vérification réussie, puis convertissent
le score en sévérité selon une grille commune :

| Score | Status | Sévérité |
|---|---|---|
| ≥ 80 | success | LOW |
| 50–79 | warning | MEDIUM |
| 30–49 | warning | HIGH |
| < 30 | error | CRITICAL |

**D'où vient quoi ? (distinction importante à faire devant le jury)**

- **Les points de contrôle** (le *quoi* : SPF, DMARC, DNSSEC, TLS 1.2+, headers HTTP, STARTTLS…)
  sont issus de **5 guides ANSSI** identifiés et référencés (ANSSI-PA-066, ANSSI-PA-009,
  SDE-NT-35, ANSSI-PA-105, ANSSI-BP-038) et, pour ce que l'ANSSI ne couvre pas, d'**OWASP**
  (Secure Headers). **La correspondance contrôle par contrôle, avec les numéros de
  recommandation exacts, est en §17** — c'est là qu'il faut aller si le jury demande les sources.
- **Le système de notation** (le *combien* : barèmes de points, seuils de sévérité, moyenne
  globale) est une **méthodologie propre au projet** — ni l'ANSSI ni l'OWASP ne définissent de
  score sur 100. Elle applique un principe classique de méthodologie d'audit (esprit ISO 19011 /
  audits PASSI) : *un constat doit reposer sur des preuves*. Un critère que le scanner n'a pas
  pu observer est marqué « non évalué » et **exclu du barème** (ex. STARTTLS quand le port 25
  est filtré, emails compromis sans clé HIBP) — il n'est ni validé ni pénalisé, et une
  recommandation invite à le vérifier manuellement.

**Point important à souligner** : les recommandations sont volontairement rédigées en
**langage non technique**, orientées TPE/PME (« connectez-vous à l'interface OVH/Gandi… »,
« demandez à votre prestataire informatique… »). C'est le cœur de la valeur du produit :
traduire un audit technique en actions compréhensibles par un gérant de PME.

En cas d'échec total d'un module (exception), il retourne quand même un `ModuleResult` avec
`score=0` et l'erreur dans `details` — **un module qui plante ne fait jamais planter le scan**.

---

## 4. Les 7 modules d'analyse en détail

### Module 1 — DNS Security (`dns_analyzer.py`)
Utilise la librairie `checkdmarc` pour auditer la configuration DNS liée à l'email et à
l'intégrité du domaine. Barème sur 100 :

| Vérification | Points | Ce que ça protège |
|---|---|---|
| **SPF** valide | 25 | Empêche l'envoi d'emails usurpant le domaine |
| **DMARC** valide | 30 | Politique anti-usurpation (détection + blocage du phishing) |
| **DNSSEC** activé | 20 | Empêche l'empoisonnement DNS (redirection vers un faux site) |
| **MX** présents | 25 | Le domaine peut recevoir des emails |

Subtilités (plusieurs correctifs intéressants à raconter, voir aussi §15) :
- Si DMARC est en `p=quarantine`, le module le signale et recommande `p=reject` (protection maximale).
- L'appel `checkdmarc` est encapsulé dans un `ThreadPoolExecutor` avec **timeout de 35 s** et
  l'option `skip_tls=True` — sans elle, checkdmarc utilise des signaux Unix pour ses timeouts
  STARTTLS, ce qui plante dans un thread (et STARTTLS est déjà testé par le module Email).
- Si checkdmarc timeout malgré tout, un **fallback maison en dnspython** vérifie quand même
  SPF, DMARC, MX et DNSSEC (requête DNSKEY directe).
- **Contre-vérification DNSSEC** : le test DNSSEC de checkdmarc produit parfois des faux
  négatifs (timeout interne). Avant de retirer les 20 points, le module interroge lui-même les
  enregistrements **DNSKEY** du domaine — s'ils existent, DNSSEC est bien actif. Si la requête
  DNSKEY elle-même échoue, le critère est marqué « non évalué » et exclu du barème (score
  recalculé sur les 80 points vérifiables).

### Module 2 — SSL/TLS Security (`ssl_analyzer.py`)
Ouvre une vraie connexion TLS sur le port 443 avec le module `ssl` de Python et récupère le
certificat via `getpeercert()`. Barème :

| Vérification | Points |
|---|---|
| Certificat valide > 30 jours | 40 (20 si expire sous 30 j, 0 si expiré) |
| Version TLS 1.2 ou 1.3 | 30 |
| Header **HSTS** présent | 30 |

**Diagnostic précis des certificats invalides** (point technique fort) : Python valide le
certificat *pendant* le handshake TLS — un certificat expiré fait donc échouer la connexion
avant même qu'on puisse le lire. Le module attrape spécifiquement `ssl.SSLCertVerificationError`,
analyse la raison (`certificate has expired`, `self-signed certificate`…), puis **rouvre une
connexion sans validation** pour lire le certificat rejeté (parsing DER via la lib
`cryptography`) et afficher la vraie date : « EXPIRÉ depuis N jours ». Testable en live sur
`expired.badssl.com` et `self-signed.badssl.com`. Score 0 / CRITICAL dans les deux cas, mais
avec un diagnostic exact au lieu d'une erreur générique.

Si le header HSTS n'a pas pu être lu (site injoignable en HTTPS depuis le scanner), les
30 points sont **exclus du barème** : score recalculé sur les 70 points vérifiables.
La recommandation HSTS est laissée au module Security Headers pour éviter les doublons ;
un message positif s'affiche quand tout est bon (TLS récent + certificat valide + HSTS actif).

### Module 3 — Security Headers (`security_headers_analyzer.py`)
Fait un `GET` sur le site et inspecte les en-têtes HTTP de réponse (référentiels OWASP/ANSSI).
**Stratégie de fallback en 3 tentatives** : HTTPS → HTTPS sans vérification de certificat →
HTTP. Ça permet d'auditer les headers même d'un site au certificat cassé. Barème :

| Header | Points | Attaque bloquée |
|---|---|---|
| `Content-Security-Policy` | 25 | XSS / injection de code |
| `Strict-Transport-Security` (HSTS) | 25 | Downgrade HTTP / interception |
| `X-Frame-Options` | 20 | Clickjacking (site intégré dans une iframe piégée) |
| `X-Content-Type-Options: nosniff` | 15 | MIME-sniffing (exécution de fichiers malveillants) |
| `Referrer-Policy` | 15 | Fuite d'URLs internes vers des sites tiers |

### Module 4 — Email Security (`email_analyzer.py`)
Complète le module DNS avec des tests **actifs mais légaux** sur la messagerie :

| Vérification | Points |
|---|---|
| Enregistrements MX présents | 25 |
| Redondance MX (≥ 2 serveurs) | 20 |
| **STARTTLS** supporté sur le serveur SMTP | 30 |
| Bannière SMTP discrète (pas de version/OS exposé) | 25 |

Subtilités intéressantes à mentionner :
- Un seul serveur MX chez **Microsoft 365 / Google Workspace** compte quand même les 20 points
  de redondance (redondance interne chez ces fournisseurs).
- **Raccourci providers cloud** : si les MX pointent vers Microsoft 365 ou Google Workspace,
  les 55 points STARTTLS/bannière sont accordés directement — ces providers garantissent
  STARTTLS et n'exposent pas de bannière verbeuse, inutile (et souvent impossible) de tester.
- Pour les autres serveurs : **une seule connexion SMTP** sert à la fois pour la bannière
  (`getwelcome()`) et le test STARTTLS (`has_extn`), en essayant le **port 25 puis le 587**
  en secours (le 587 est le port de soumission, souvent ouvert quand le 25 est filtré).
- Si les **deux ports sont filtrés** (très fréquent : pare-feux, et port 25 bloqué en sortie
  par Oracle Cloud sur le VPS), les 55 points STARTTLS/bannière sont **exclus du barème** :
  le score est calculé sur les 45 points vérifiables (MX + redondance) puis remis à l'échelle
  sur 100. Principe : *on ne pénalise pas le domaine pour une limite du scanner* —
  la recommandation précise que ces critères n'ont pas pu être évalués.
- Bannière « verbeuse » = contient `version`, `ubuntu`, `debian`, `centos` ou `postfix` →
  information utile à un attaquant pour cibler des CVE connues.

### Module 5 — Subdomain Takeover (`subdomain_takeover_analyzer.py`)
Détecte les sous-domaines pointant (via CNAME) vers des services cloud **abandonnés**, qu'un
attaquant pourrait revendiquer pour servir du contenu en votre nom. Fonctionnement :

1. Énumération de **34 sous-domaines courants** (`www`, `mail`, `api`, `dev`, `staging`, `vpn`…).
2. Pour chacun : résolution du **CNAME**. Pas de CNAME → pas de risque, on passe.
3. Le CNAME est comparé à un dictionnaire de **14 signatures de services** vulnérables
   (GitHub Pages, Heroku, Shopify, Azure, S3, Fastly, Zendesk… — source : projet
   [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)).
4. Si le CNAME matche, on fait un GET HTTP et on cherche la **signature d'erreur du service**
   dans le corps de la page (ex. GitHub : *"There isn't a GitHub Pages site here"*) →
   si présente, la ressource est **orpheline = vulnérable**.

Scoring inversé : on **part de 100** et on déduit — **−40** par sous-domaine réellement
vulnérable (sévérité CRITICAL), **−10** par CNAME tiers « à surveiller » (HIGH).
L'analyse complète est bornée par un **timeout global de 45 s** (ThreadPoolExecutor) :
34 résolutions DNS + d'éventuels GET HTTP peuvent traîner, le scan ne doit jamais geler.

### Module 6 — Domain Expiration (`domain_expiration.py`)
Interroge le **WHOIS** (`python-whois`) pour la date d'expiration du nom de domaine. Un domaine
expiré = site et emails morts, et risque de rachat par un tiers. Barème par paliers :

| Jours restants | Score | Sévérité |
|---|---|---|
| expiré | 0 | CRITICAL |
| < 7 j | 0 | CRITICAL |
| < 30 j | 30 | HIGH |
| < 90 j | 60 | MEDIUM |
| < 180 j | 85 | LOW |
| ≥ 180 j | 100 | LOW |

Difficultés techniques gérées (bon exemple de robustesse à citer) :
- `python-whois` retourne la date sous des formes variables selon le TLD : `datetime`, `str`,
  `list`, avec ou sans timezone → fonction `_parse_expiration_date()` qui normalise tout en
  datetime UTC-aware.
- Timeout de 15 s via `ThreadPoolExecutor` (les serveurs WHOIS sont parfois très lents) ;
  si timeout ou date indisponible → score neutre de 50 avec recommandation de vérifier
  manuellement.

### Module 7 — OSINT Breaches (`osint_breaches.py`)
Croise **trois sources de renseignement en sources ouvertes** :

1. **HIBP `/breaches` (gratuit, sans clé)** : le domaine est-il lui-même **source** d'une fuite
   de données connue ? (comparaison avec la base publique Have I Been Pwned, ~1000 fuites ;
   gère les TLD composés type `.co.uk`).
2. **URLhaus (abuse.ch, gratuit)** : le domaine héberge-t-il des **URLs de distribution de
   malware** ? Vérifie aussi les blacklists Spamhaus DBL et SURBL.
3. **HIBP `/breacheddomain` (clé API payante, optionnelle)** : combien d'**adresses email
   @domaine** apparaissent dans des fuites ? (mots de passe d'employés compromis).

Le score est une matrice de gravité : malware + source de fuite = 0 (CRITICAL) ; malware seul
ou fuites multiples = 15 ; source d'une fuite = 35 ; emails compromis gradués (≤5 → 60,
≤20 → 30, >20 → 0) ; rien trouvé = 100. Si la clé API n'est pas configurée, la partie « emails »
est marquée « non vérifié » et **exclue du score** (même principe que le module Email : on ne
pénalise pas ce que le scanner n'a pas pu vérifier) — les vérifications gratuites restantes
suffisent alors pour un 100.

### Bonus — Détection de plateforme (`platform_detector.py`)
Exécutée **avant** les modules, sans score propre : GET sur la page d'accueil et recherche de
signatures dans le HTML (`shopify`, `wix`, `wp-content` → WordPress). Enrichit le rapport
(le contexte « site Shopify » change les recommandations pertinentes).

---

## 5. Persistance : la base de données

SQLite via SQLAlchemy, 2 tables (`db_models.py`) :

```
scans                              modules
─────                              ───────
scan_id (PK, UUID)          1──N   id (PK, autoincrement)
domain (indexé)                    scan_id (FK → scans, cascade delete)
platform                           module_name
timestamp                          status / severity / score
overall_score                      details (JSON)
summary                            recommendations (JSON)
critical/high/medium/low_issues
```

- Les tables sont créées au démarrage (`Base.metadata.create_all` dans le `lifespan` FastAPI).
- Les colonnes `details` et `recommendations` sont en **JSON** : chaque module a des détails de
  forme différente, le JSON évite un schéma rigide.
- Deux convertisseurs font le pont entre Pydantic (API) et SQLAlchemy (DB) :
  `_result_to_db()` et `_db_to_result()` dans `routes.py`.
- Grâce à la persistance, le **PDF et le chat restent disponibles après le scan** via le
  `scan_id`, même après rechargement de la page.

---

## 6. Le rapport PDF (`pdf_report.py` + `templates/report.html.j2`)

Pipeline : **données du scan → template Jinja2 (HTML/CSS) → WeasyPrint → bytes PDF**.

- Le template Jinja2 reçoit les modules **triés par sévérité** (critique d'abord) et la liste
  agrégée de toutes les recommandations, également priorisée.
- Des filtres Jinja2 personnalisés gèrent la présentation : couleur selon le score
  (`#DC2626` rouge < 40 … `#16A34A` vert ≥ 85), labels français (CRITIQUE/ÉLEVÉ/MOYEN/BON/
  EXCELLENT), formatage des valeurs (listes, dicts, booléens → « Oui/Non »), dates en français.
- WeasyPrint transforme le HTML en PDF (moteur de rendu CSS complet, gère `@page` pour les
  fonds de page — un bug de PDF « tout noir » a d'ailleurs été corrigé à ce niveau).
- Le PDF est servi en streaming : `GET /api/v1/scan/{scan_id}/pdf` →
  `Content-Disposition: attachment; filename="rapport-eon-<domaine>-<date>.pdf"`.
- Côté Docker, WeasyPrint nécessite des libs système (Pango, HarfBuzz, Fontconfig) installées
  dans le `Dockerfile`.

**Pourquoi ce choix ?** Écrire le rapport en HTML/CSS est beaucoup plus productif que de
dessiner un PDF programmatiquement (ReportLab) : mise en page déclarative, itération rapide.

---

## 7. L'assistant IA (`api/chat.py`)

Un chatbot contextualisé sur **les résultats du scan en cours** :

1. Le frontend appelle `POST /api/v1/chat/{scan_id}` avec le message + l'historique de la
   conversation (l'historique est géré côté client, le serveur est stateless).
2. Le backend recharge le scan depuis la base et construit un **system prompt** qui injecte :
   domaine, score global, compteurs d'issues, et la liste des modules avec scores et
   recommandations.
3. Appel de l'**API Anthropic** (modèle `claude-haiku-4-5` — petit modèle : rapide et peu
   coûteux, suffisant pour de l'explication guidée) en **streaming**.
4. Les tokens sont relayés au navigateur en SSE au fil de l'eau → effet « machine à écrire ».

Garde-fous dans le system prompt : répondre uniquement en français, prioriser les actions
critiques, et **refuser les sujets hors cybersécurité du domaine scanné** (anti-détournement
du chatbot). Si `ANTHROPIC_API_KEY` n'est pas configurée → HTTP 503 propre.

---

## 8. Le frontend (`frontend/app.js`)

SPA **sans framework** (~580 lignes de JS vanilla) — choix assumé : pas de build, pas de
dépendances, déploiement = `git pull` (nginx sert les fichiers statiques tels quels).

- **Architecture** : un objet d'état global `S` (page courante, résultat, messages du chat…) +
  une fonction `render()` qui reconstruit le HTML de la page à chaque changement d'état —
  le même principe qu'un framework réactif, en version minimale.
- **3 pages** : `scan` (formulaire) → `loading` (barre de progression alimentée par le SSE,
  liste des 7 modules avec check ✓ au fur et à mesure) → `results`.
- **Page résultats** : cartes de stats (score global coloré, nb de modules critiques/élevés),
  liste des modules **dépliables** (détails clé/valeur + recommandations), colonne « Actions
  prioritaires » = toutes les recommandations triées par sévérité, widget de chat flottant.
- **Lecture du SSE** : `fetch` + `response.body.getReader()` + `TextDecoder`, parsing des
  lignes `data: {...}` (pas d'`EventSource` car il faut un POST).
- **Sécurité XSS** : toute donnée dynamique passe par un helper d'échappement `h()` avant
  insertion dans le HTML.
- **Health check** : ping de `/health` toutes les 30 s → pastille « En ligne / Hors ligne ».
- Téléchargement du PDF via `blob` + lien temporaire (`URL.createObjectURL`).

---

## 9. Backend : points d'architecture à valoriser

- **FastAPI + Pydantic** : validation automatique des entrées, documentation OpenAPI générée
  (`/api/docs` — Swagger UI, pratique pour la démo).
- **Async + threadpool** : les analyzers utilisent des librairies synchrones (requests,
  dnspython, smtplib) ; `run_in_threadpool` les exécute hors de l'event loop → le serveur
  reste réactif pendant un scan (~30-60 s).
- **CORS** configuré explicitement (origines localhost + IP du VPS), `allow_credentials=False`
  pour éviter un bug de preflight OPTIONS.
- **Config centralisée** (`config.py`, pydantic-settings) : clés API et paramètres dans un
  `.env` jamais commité (`.env.example` fourni).
- **Timeouts partout** : chaque appel réseau a un timeout (10-20 s), les librairies bloquantes
  (checkdmarc, whois) sont enveloppées dans des `ThreadPoolExecutor` avec timeout — un domaine
  « pathologique » ne peut pas geler le scan.
- **Résilience** : chaque module attrape ses exceptions et retourne un résultat dégradé au lieu
  de faire échouer le scan complet.

### Endpoints de l'API

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/api/v1/scan` | Scan complet en un bloc (JSON) |
| POST | `/api/v1/scan/stream` | Scan avec progression SSE (utilisé par le front) |
| GET | `/api/v1/scan/{scan_id}` | Relire un scan depuis la base |
| GET | `/api/v1/scan/{scan_id}/pdf` | Générer et télécharger le rapport PDF |
| DELETE | `/api/v1/scan/{scan_id}` | Supprimer un scan (+ ses modules, cascade) |
| POST | `/api/v1/chat/{scan_id}` | Chatbot IA (streaming SSE) |
| GET | `/api/v1/platforms` | Liste des plateformes détectables |
| GET | `/health` | Health check |

---

## 10. Tests

- **Tests unitaires** (un fichier par module dans `backend/tests/`) : les appels réseau sont
  **mockés** → rapides, déterministes, exécutables hors ligne. On teste la logique de scoring
  (ex. « SPF manquant → 25 points en moins + recommandation présente »).
- **Tests d'intégration** (`test_integration.py`) : vrais appels réseau vers des domaines
  stables (google.com, cloudflare.com) pour valider le comportement de bout en bout.
- Lancement : `pytest tests/ -v` dans `backend/`.

---

## 11. Déploiement

- **VPS Oracle Cloud** (Ubuntu).
- **Backend** : conteneur Docker (`python:3.11-slim` + libs Pango pour WeasyPrint), lancé via
  `docker compose`, exposé sur le port 8000. Mise à jour :
  `docker compose build eon-backend && docker compose up -d eon-backend`.
- **Frontend** : fichiers statiques servis directement par **nginx**. Mise à jour : `git pull`.
- Le frontend construit l'URL de l'API dynamiquement
  (`http://${window.location.hostname}:8000`) → le même code marche en local et en prod.

---

## 12. Questions probables du jury (et réponses)

**« Le scan est-il légal ? »**
Oui : uniquement des requêtes qu'un navigateur ou un serveur mail ferait normalement —
résolution DNS, connexion TLS, GET HTTP, WHOIS public, bases OSINT publiques (HIBP, URLhaus).
Aucun scan de ports agressif, aucune exploitation, aucun brute-force.

**« Pourquoi séquentiel et pas parallèle ? »**
Choix pour la lisibilité de la progression (SSE module par module) et pour rester courtois
envers la cible (pas de rafale de requêtes). La parallélisation (asyncio.gather) est une
évolution identifiée.

**« Pourquoi SQLite ? »**
Volume faible (un enregistrement par scan), pas de concurrence forte, zéro administration.
Grâce à SQLAlchemy, migrer vers PostgreSQL = changer `DATABASE_URL` (psycopg2 est déjà dans
les requirements).

**« Comment sont calculés les scores ? »**
Grille de points par vérification, définie par module (voir §4), moyenne simple pour le score
global. Les seuils de sévérité sont harmonisés entre modules (§3). Limite assumée : la moyenne
simple ne pondère pas les modules entre eux — une pondération par criticité serait une évolution.

**« Le scoring vient-il de l'ANSSI ? »**
Non, et il faut être précis là-dessus : l'ANSSI et l'OWASP fournissent **les points de
contrôle** (quoi vérifier et pourquoi), pas de système de notation. Le score sur 100 est
**notre méthodologie**, avec un principe emprunté aux méthodes d'audit classiques : on ne note
que ce qu'on a pu vérifier — un critère inobservable (port 25 filtré, clé API absente) est
« non évalué » et sort du barème au lieu d'être noté arbitrairement.

**« Quelle recommandation ANSSI précisément, pour tel contrôle ? »**
Le tableau de correspondance complet est en **§17** : chaque contrôle est relié à son guide
(référence + date) et au **numéro de recommandation**. Exemples à avoir en tête :
STARTTLS = **R42** (ANSSI-PA-066), SPF = **R44**, DMARC = **R48+**, DNSSEC = **R50+** (PA-066) et
**R14** (ANSSI-PA-105), HSTS = **R2** et CSP = **R14** (ANSSI-PA-009), TLS 1.2/1.3 = **R3**
(guide TLS SDE-NT-35). Et savoir dire ce qui ne vient PAS de l'ANSSI : `nosniff` (OWASP),
le subdomain takeover (can-i-take-over-xyz) et l'OSINT (HIBP/URLhaus).

**« Que se passe-t-il si une API externe est en panne ? »**
Timeouts + try/except par module : le module concerné rend un score dégradé avec un message
explicite, le reste du scan continue.

**« Pourquoi pas de framework frontend ? »**
Périmètre réduit (3 vues), pas de build à maintenir, déploiement trivial. Le pattern
état → render() reproduit l'essentiel d'un framework réactif.

### Limites connues / pistes d'évolution
- Parallélisation des modules pour réduire la durée du scan.
- Historique des scans visible dans l'UI (les modèles `HistoryItem`/`HistoryResponse` existent
  déjà côté Pydantic, l'endpoint reste à brancher).
- HTTPS sur le frontend en production (actuellement HTTP sur l'IP du VPS).
- DKIM non vérifié (nécessite de connaître le sélecteur du domaine, voir §14).
- Le paramètre `include_subdomains` est transmis mais pas encore exploité par les modules.
- Pondération des modules dans le score global.

---

## 13. Plan de démo suggéré (5 minutes)

1. Page d'accueil → lancer un scan sur un domaine réel (préparer un domaine avec des
   résultats intéressants, ni parfait ni catastrophique).
2. Pendant le chargement : expliquer le SSE et les 7 modules qui défilent.
3. Page résultats : lire le score, déplier un module « warning », montrer le langage
   accessible des recommandations.
4. Poser une question au chatbot (« Par quoi je commence ? »).
5. Télécharger le PDF et le montrer.
6. Bonus : ouvrir `/api/docs` pour montrer l'API documentée automatiquement.

---

## 14. Cours accéléré — les notions cyber à maîtriser pour le jury

Pour chaque notion : comment ça marche, pourquoi on la vérifie, et la question piège associée.

### 14.1 DNS — la base de tout

Le DNS traduit un nom (`exemple.com`) en adresses. Les types d'enregistrements que l'outil
manipule :

| Type | Contenu | Utilisé par |
|---|---|---|
| **A / AAAA** | Adresse IP du serveur | Validation du domaine avant scan |
| **MX** | Serveurs de messagerie entrants, avec priorité | Modules DNS et Email |
| **TXT** | Texte libre — c'est là que vivent SPF et DMARC | Module DNS |
| **CNAME** | Alias vers un autre nom (ex. `blog.x.com → x.github.io`) | Module Takeover |
| **DNSKEY / RRSIG / DS** | Clés publiques et signatures DNSSEC | Module DNS |

### 14.2 SPF (Sender Policy Framework)

- **Mécanisme** : un enregistrement TXT sur le domaine (`v=spf1 include:_spf.google.com -all`)
  qui **liste les serveurs autorisés à envoyer** des emails au nom du domaine. Le serveur
  *destinataire* compare l'IP de l'expéditeur à cette liste.
- **Ce que ça bloque** : un spammeur qui envoie depuis sa propre machine des mails
  `De: patron@votre-pme.fr`.
- **Limite (question piège)** : SPF vérifie l'expéditeur *technique* (enveloppe SMTP), pas le
  `De:` affiché dans le client mail. Il casse aussi sur les transferts de mails. C'est pour ça
  que DMARC existe.
- Le `-all` (rejet) est plus strict que `~all` (softfail).

### 14.3 DKIM (DomainKeys Identified Mail) — et pourquoi on ne le teste PAS

- **Mécanisme** : le serveur émetteur **signe cryptographiquement** chaque email ; la clé
  publique est publiée en DNS sous `selecteur._domainkey.domaine.com`.
- **Question piège quasi certaine : « pourquoi votre outil ne vérifie pas DKIM ? »**
  Réponse : la clé est publiée sous un **sélecteur choisi librement** par l'expéditeur
  (`google._domainkey`, `s1._domainkey`, `k2025._domainkey`…). Sans recevoir un vrai email du
  domaine (qui contient le nom du sélecteur dans son en-tête), on ne peut pas deviner où
  chercher. Un scan passif ne peut donc pas auditer DKIM de façon fiable — on pourrait au
  mieux tester une liste de sélecteurs courants (piste d'évolution).

### 14.4 DMARC (Domain-based Message Authentication, Reporting & Conformance)

- **Mécanisme** : TXT sur `_dmarc.domaine.com`. DMARC s'appuie sur SPF **et** DKIM et ajoute
  la notion d'**alignement** : le domaine vérifié par SPF/DKIM doit correspondre au domaine
  du `De:` visible. C'est lui qui protège vraiment contre l'usurpation d'affichage.
- **La politique `p=`** (ce que le destinataire doit faire d'un mail non conforme) :
  `none` (surveiller seulement) < `quarantine` (spam) < `reject` (refus pur). L'outil
  recommande `reject`.
- `rua=mailto:...` : adresse où les destinataires envoient des **rapports agrégés** — c'est de
  la télémétrie gratuite sur qui usurpe votre domaine.
- **Hiérarchie à retenir** : SPF et DKIM sont les mécanismes de preuve, DMARC est la politique
  qui les exploite. Sans DMARC, SPF seul ne bloque pas l'usurpation du `De:` affiché.

### 14.5 DNSSEC

- **Problème résolu** : le DNS classique n'est pas authentifié — un attaquant peut
  **empoisonner le cache** d'un résolveur et rediriger `votrebanque.fr` vers son serveur.
- **Mécanisme** : chaque zone signe ses enregistrements (RRSIG) avec une clé (DNSKEY), et la
  zone parente publie l'empreinte de cette clé (DS) — une **chaîne de confiance** remonte
  jusqu'à la racine du DNS. Le résolveur peut ainsi vérifier que la réponse n'a pas été altérée.
- **Détection par l'outil** : présence d'enregistrements DNSKEY (+ validation checkdmarc).
- **Question piège : « google.com n'a pas DNSSEC, votre outil le pénalise ? »** Oui, 80/100 en
  DNS — et c'est factuellement correct : Google a fait le choix assumé de ne pas signer
  google.com (ils misent sur d'autres protections). L'outil rapporte des faits, le contexte
  est expliqué dans la recommandation. Ça montre que le score n'est pas « magique ».

### 14.6 TLS et certificats

- **Le handshake TLS** : le client et le serveur négocient version + chiffrement, le serveur
  présente son **certificat** (identité + clé publique, signé par une autorité de
  certification), le client vérifie la chaîne de confiance, la validité temporelle et la
  correspondance du nom de domaine. Ensuite seulement le trafic est chiffré.
- **Versions** : TLS 1.2 (2008) et 1.3 (2018) sont sûres ; TLS 1.0/1.1 et SSLv3 sont
  dépréciées (attaques POODLE, BEAST…). « SSL » est l'ancien nom — dire TLS.
- **Certificat expiré** = les navigateurs affichent un avertissement plein écran → perte de
  trafic immédiate pour une PME. Let's Encrypt fournit des certificats gratuits renouvelés
  automatiquement (90 jours), d'où la recommandation.
- **Auto-signé / autorité inconnue / mauvais domaine** : trois raisons de rejet distinctes que
  l'outil sait différencier (via `verify_message` du handshake).

### 14.7 HSTS (HTTP Strict Transport Security)

- **Header** : `Strict-Transport-Security: max-age=31536000; includeSubDomains`.
- **Attaque bloquée — SSL stripping** : sans HSTS, un utilisateur qui tape `site.fr` part en
  HTTP ; un attaquant en position d'interception (Wi-Fi public) peut maintenir la connexion en
  HTTP et lire/modifier tout le trafic. Avec HSTS, après la première visite le navigateur
  **refuse** de parler HTTP au site pendant `max-age` secondes.
- Bon exemple réel : la chaîne de redirection `esgi.fr → http://www.esgi.fr → https://...`
  passe par un saut HTTP en clair — exactement ce que HSTS éviterait.

### 14.8 Les autres en-têtes HTTP de sécurité

| Header | Attaque bloquée | En une phrase |
|---|---|---|
| **Content-Security-Policy** | XSS | Liste blanche des sources de scripts/styles/images ; un script injecté par un attaquant ne s'exécute pas s'il ne vient pas d'une source autorisée |
| **X-Frame-Options** | Clickjacking | Interdit d'afficher le site dans une iframe — sinon un site piège superpose des boutons invisibles au-dessus du vôtre |
| **X-Content-Type-Options: nosniff** | MIME sniffing | Empêche le navigateur de « deviner » le type d'un fichier et d'exécuter comme script un fichier déguisé |
| **Referrer-Policy** | Fuite d'infos | Contrôle ce que le header `Referer` révèle aux sites tiers (URLs internes, tokens dans l'URL…) |

### 14.9 STARTTLS et la messagerie

- SMTP date d'une époque sans chiffrement : par défaut, un mail transite **en clair** entre
  serveurs. **STARTTLS** permet de « surclasser » la connexion en TLS sur le même port.
- Ports : **25** = relais entre serveurs, **587** = soumission (client → serveur). Le 25 est
  très souvent bloqué en sortie par les hébergeurs cloud (anti-spam) — d'où notre fallback 587
  et l'exclusion du barème si les deux sont inaccessibles.
- **Bannière SMTP** : la ligne d'accueil du serveur (`220 mail.x.fr ESMTP Postfix (Ubuntu)`).
  Si elle révèle logiciel/version/OS, un attaquant sait immédiatement quelles CVE tester.

### 14.10 Subdomain takeover

- **Scénario complet** : une PME crée `promo.pme.fr` en CNAME vers `pme.github.io` pour un
  événement. L'événement passe, on supprime la page GitHub **mais pas le CNAME**. N'importe
  qui peut alors créer un GitHub Pages nommé `pme.github.io` → il contrôle ce qui s'affiche
  sur `promo.pme.fr`, avec le nom de la PME et même la possibilité d'obtenir un certificat
  TLS valide. Phishing parfait.
- **Détection en 2 temps** (important) : le CNAME vers un service cloud ne suffit pas — il
  faut vérifier que la ressource est **orpheline**, via la page d'erreur caractéristique du
  service (« There isn't a GitHub Pages site here »). CNAME seul = « à surveiller » (−10),
  CNAME + page d'erreur = vulnérable (−40).

### 14.11 WHOIS et expiration de domaine

- Base publique des enregistrements de domaines (registrar, dates). Un domaine expiré peut
  être racheté par n'importe qui — qui récupère alors le trafic **et les emails** de la PME.
- Cas réels célèbres d'entreprises ayant perdu leur domaine par simple oubli de renouvellement.
- Limite : certains TLD (dont parfois le `.fr`) limitent les données WHOIS (RGPD) → si la date
  est illisible, score neutre 50 + recommandation de vérifier chez son registrar.

### 14.12 OSINT (Open Source Intelligence)

- Renseignement en **sources ouvertes** : on n'attaque rien, on consulte des bases publiques.
- **Have I Been Pwned** : base de ~1000 fuites de données publiques. Deux usages : le domaine
  comme *source* d'une fuite (gratuit), et les emails du domaine *présents dans* des fuites
  (API payante — mots de passe d'employés dans la nature = risque de credential stuffing).
- **URLhaus (abuse.ch)** : base collaborative d'URLs distribuant des malwares. Un site de PME
  compromis sert souvent de point de distribution sans que le gérant le sache.
- Pourquoi c'est pertinent pour une TPE : ce sont les mêmes sources que consultent les
  attaquants pour préparer une campagne.

### 14.13 Vocabulaire divers susceptible de tomber

- **Scan passif vs actif** : passif = requêtes légitimes qu'un client normal ferait (notre
  cas) ; actif = sonder des failles (scan de ports agressif, fuzzing) — interdit sans mandat.
- **SSE vs WebSocket** : SSE = flux unidirectionnel serveur→client sur HTTP simple ;
  WebSocket = bidirectionnel, protocole dédié. Notre besoin est unidirectionnel → SSE.
- **CVE** : identifiant public d'une vulnérabilité connue (ex. CVE-2024-XXXX).
- **Credential stuffing** : rejouer des couples email/mot de passe issus de fuites sur
  d'autres services.
- **Typosquatting** : enregistrer un domaine à une faute de frappe du vrai
  (`cloudfare.com` vs `cloudflare.com` — on l'a vécu en test, voir §15).

---

## 15. Anecdotes de développement (à raconter en soutenance si on creuse la technique)

Ces « bugs de guerre » montrent une vraie démarche d'ingénierie — les garder en réserve pour
les questions techniques :

1. **checkdmarc plantait dans les threads.** Le module DNS retournait parfois 0 avec une
   erreur obscure « signal only works in main thread ». Cause : checkdmarc utilise des
   signaux Unix pour ses timeouts STARTTLS, or les signaux ne marchent que dans le thread
   principal — et nos analyzers tournent dans un threadpool. Correctif : `skip_tls=True`
   (le STARTTLS est testé ailleurs). Leçon : le comportement dépendait de *comment* le serveur
   démarrait, d'où des bugs « ça marche sur le VPS mais pas en local ».
2. **Faux négatifs DNSSEC.** cloudflare.com sortait parfois « DNSSEC désactivé » alors que le
   domaine est signé — le test interne de checkdmarc échoue par intermittence. Correctif :
   contre-vérification directe des enregistrements DNSKEY avant de retirer des points.
   Leçon : ne jamais pénaliser sur un échec de *mesure*.
3. **cloudfare.com ≠ cloudflare.com.** En testant, on scannait un typosquat sans s'en rendre
   compte — et l'outil avait *raison* : ce domaine (possédé par Cloudflare pour rattraper la
   faute de frappe) n'a réellement pas DNSSEC. Une lettre de différence = deux postures de
   sécurité. Excellente illustration du typosquatting.
4. **Les certificats expirés étaient invisibles.** Python valide le certificat pendant le
   handshake : un certificat expiré faisait planter la connexion avant qu'on puisse le lire,
   et l'outil affichait « vérifier que le site utilise HTTPS » — faux diagnostic. Correctif :
   attraper l'erreur de validation, se reconnecter sans validation et parser le certificat
   rejeté pour afficher « EXPIRÉ depuis N jours ».
5. **Le port 25 bloqué par Oracle Cloud.** Sur le VPS, impossible de tester STARTTLS : le
   cloud bloque le port 25 en sortie (anti-spam). D'abord traité en « bénéfice du doute »
   (+30 points gratuits), puis remplacé par l'exclusion du barème — plus honnête. Ajout du
   fallback port 587 et du raccourci M365/Google pour réduire les cas invérifiables.
6. **Un scan gelait tout le serveur.** L'endpoint `/scan` était déclaré `async` mais appelait
   7 analyzers synchrones : l'event loop était bloqué ~1 minute, plus aucune requête ne
   passait. Correctif : endpoint en `def` (FastAPI l'exécute alors dans un threadpool).
7. **Le PDF sortait tout noir dans Firefox.** Un fond posé via la règle CSS `@page` dans le
   template WeasyPrint rendait le PDF illisible dans certains lecteurs. Revert + fond géré
   autrement.
8. **esgi.fr à 0/100 en headers.** Vérifié à la main au `curl` : le site (WordPress derrière
   nginx/Azure Gateway) n'envoie réellement aucun des 5 en-têtes de sécurité, et la
   redirection passe même par un saut HTTP en clair. L'outil détecte un vrai problème,
   démontrable en une commande devant le jury.

---

## 16. Plan de diapositives — consignes officielles et déroulé

### 16.1 Les consignes données par l'école (à respecter à la lettre)

| Consigne | Conséquence sur le diaporama |
|---|---|
| **20 minutes**, démonstration **comprise** | ~15 min de parole + ~5 min de démo |
| **Minimum 15 diapos** | On vise **17** (voir 16.3) |
| **Cahier de projet / architecture au début** | Diapos 4 à 7, avant tout le reste |
| **Ne pas parler de gestion de projet** | ❌ Pas de diapo planning, Git, répartition des tâches, méthode agile. C'est une **soutenance de projet**, pas de management |
| **Ne pas parler de code, ne pas le montrer** | ❌ Zéro capture d'écran de code, zéro nom de fonction ou de librairie à l'écran. On explique **la démarche**, pas l'implémentation |
| **Ne pas meubler** | Chaque diapo porte une idée utile ; si on n'a rien à dire dessus, on la supprime |
| **Démonstration préparée en amont** | Scénario répété, dans le temps imparti |
| **Toujours une vidéo de secours** | À enregistrer **avant** le jour J |
| **Faire une conclusion** | Diapo finale obligatoire |
| **Numéroter les diapos** | Numéro visible sur chaque diapo |
| **Se présenter** | Diapo « équipe » en début — qui on est, pas qui a fait quoi |
| **Tenue professionnelle** | Pas de baskets, tenue correcte |

> ⚠️ **Deux diapos de mon plan précédent sautent** : celle sur le workflow Git / la répartition des
> tâches (interdit : gestion de projet) et le détail technique du code dans les blocs « comment on
> vérifie » (interdit : code). Le contenu technique reste **à l'oral et en réserve pour les
> questions**, jamais à l'écran.

### 16.2 « Pas de code » : comment parler technique sans parler code

C'est la contrainte la plus piégeuse — un projet d'audit de sécurité **est** technique. La règle :
on parle **du protocole, de la démarche et du résultat**, pas de l'implémentation.

| ❌ À bannir (diapo et oral) | ✅ À dire à la place |
|---|---|
| « on utilise `checkdmarc` dans un `ThreadPoolExecutor` avec `skip_tls=True` » | « on interroge les enregistrements DNS du domaine, avec un garde-fou qui empêche une requête lente de bloquer le scan » |
| « on attrape `ssl.SSLCertVerificationError` et on parse le DER » | « quand le certificat est rejeté, on rouvre une connexion pour lire quand même le certificat et dire précisément **pourquoi** il est refusé : expiré, auto-signé, mauvais domaine » |
| « `smtplib` sur le port 25 puis 587 » | « on se connecte au serveur de messagerie comme le ferait un autre serveur mail, et on regarde s'il propose le chiffrement » |
| Capture d'écran de code | Capture de **l'interface**, du **rapport PDF**, ou un **schéma** |

Les anecdotes de développement (§15) restent racontables **à l'oral** — mais en version
fonctionnelle : « un domaine correctement configuré ressortait parfois comme non protégé, on a
compris que la vérification échouait par intermittence, donc on la double par un second contrôle
indépendant ». Aucun nom de librairie n'est nécessaire pour que ce soit impressionnant.

### 16.3 Le déroulé — 17 diapos / 20 minutes

| # | Diapo | Temps | Contenu |
|---|---|---|---|
| 1 | **Titre** | 0:20 | Logo ÉON, « Audit de sécurité automatisé pour TPE/PME », noms, année, URL de démo |
| 2 | **Qui sommes-nous** | 0:40 | Présentation de l'équipe (prénoms, filière). **Pas** « qui a fait quoi » (= gestion de projet) |
| 3 | **Sommaire** | 0:20 | Les 5 parties : cadrage · solution · analyses · démo · bilan |
| 4 | **Cahier de projet — le contexte** | 1:30 | Les TPE-PME sont ciblées, sans RSSI ni budget d'audit, et ne savent pas quoi vérifier |
| 5 | **Cahier de projet — objectifs & périmètre** | 1:30 | Objectifs, cible utilisateur, ce qui est **dans** le périmètre / ce qui n'y est pas (100 % passif, aucune exploitation) |
| 6 | **L'existant / les concurrents** | 1:30 | SSL Labs, securityheaders.com, MXToolbox, Hardenize : chacun ne couvre **qu'une** brique, en anglais, pour des experts |
| 7 | **Architecture du projet** | 1:30 | Le schéma (§1) : interface → serveur d'analyse → 7 modules → base → rapport PDF → assistant IA. **Un schéma, pas du code** |
| 8 | **Notre alternative** | 1:00 | Capture de la page résultats : un domaine → 7 analyses → 1 score → 1 rapport → 1 assistant |
| 9 | **Méthodologie de scoring** ⭐ | 2:00 | Contrôles issus de 5 guides ANSSI + OWASP ; **notation = notre méthodologie** ; **un critère non vérifiable est exclu du barème** |
| 10 | **Vue d'ensemble des 7 analyses** | 1:30 | Tableau : analyse / ce qu'elle vérifie / attaque bloquée / référentiel |
| 11 | **Zoom 1 — Messagerie** (4 temps) | 1:30 | Usurpation d'identité, mails en clair. **R42, R44, R48+ (ANSSI-PA-066)** |
| 12 | **Zoom 2 — Subdomain takeover** (4 temps) | 1:30 | Le scénario d'attaque. ⚠️ **Pas d'ANSSI** → can-i-take-over-xyz |
| 13 | **Zoom 3 — En-têtes de sécurité** (4 temps) | 1:00 | Les 5 en-têtes + **esgi.fr à 0/100**. R2/R14/R18/R21 (ANSSI-PA-009) ; ⚠️ nosniff = OWASP |
| 14–15 | **DÉMONSTRATION** ⭐ | 4:30 | Scénario répété, **dans** les 20 min. Vidéo de secours prête |
| 16 | **Bilan & voies d'amélioration** | 1:30 | Ce qui fonctionne aujourd'hui / limites assumées / évolutions |
| 17 | **Conclusion** ⭐ | 1:00 | Obligatoire. 3 messages + URL de démo. Puis « merci, des questions ? » |
| | **Total** | **~20:00** | |

**Répartition macro :** cadrage 5 min · solution et méthode 5 min · analyses 4 min · démo 4,5 min ·
bilan et conclusion 2,5 min.

**Numéro de diapo visible sur chacune** (consigne explicite) — le format `7 / 17` est le plus lisible.

### 16.4 Le gabarit « 4 temps » (diapos 11, 12, 13)

Un seul visuel en 4 blocs, **sans une ligne de code** :

```
┌────────────────────────────┬────────────────────────────┐
│ ① LE PROBLÈME              │ ② CE QUE LA PROTECTION      │
│ L'attaque + l'impact pour   │    APPORTE                  │
│ une PME (1 phrase, 1 icône) │ À quoi sert la contre-      │
│                             │ mesure (1 phrase)           │
├────────────────────────────┼────────────────────────────┤
│ ③ COMMENT NOUS LE          │ ④ LE RÉFÉRENTIEL           │
│    VÉRIFIONS               │ ANSSI-PA-0xx — R42          │
│ La démarche en 1 phrase     │ « intitulé exact »          │
│ (pas d'implémentation)      │                             │
└────────────────────────────┴────────────────────────────┘
```

⚠️ **Le bloc ④ n'existe pas partout.** L'ANSSI ne couvre **ni** le subdomain takeover, **ni**
l'OSINT, **ni** `X-Content-Type-Options`. Sur ces diapos, titrez le bloc « **Référentiel** » et
citez la vraie source. Le dire franchement est un point fort ; inventer une référence devant un
jury de professionnels est éliminatoire.

**On ne détaille que 3 analyses sur 7.** Les 4 autres sont sur la diapo de vue d'ensemble (10) et
préparées **pour les questions** (§16.5) — c'est le bon usage des 10 min de Q&R, et ça évite de
meubler.

### 16.5 Contenu des 4 temps, pour les 7 analyses

*(Le temps ③ est rédigé en langage fonctionnel — utilisable tel quel à l'écran et à l'oral.)*

#### 1 — DNS (SPF, DMARC, DNSSEC, MX)
- **① Problème** : n'importe qui peut envoyer un mail au nom du domaine (phishing contre les
  clients de la PME) ; sans DNSSEC, un visiteur peut être redirigé vers un faux site. *(§14.2/4/5)*
- **② Ce que ça apporte** : SPF déclare les serveurs autorisés à émettre ; DMARC est la politique
  qui décide du sort des mails non conformes ; DNSSEC garantit l'intégrité des réponses DNS.
- **③ Comment on vérifie** : on lit les enregistrements publics du domaine et on contrôle leur
  présence et leur contenu ; un second contrôle indépendant confirme DNSSEC pour éviter les faux
  négatifs.
- **④ ANSSI** : **R44** (SPF), **R48+** (DMARC), **R50+** (DNSSEC) — **ANSSI-PA-066** ; **R14**
  « Activer DNSSEC » — **ANSSI-PA-105**.

#### 2 — SSL/TLS
- **① Problème** : certificat expiré = alerte de danger plein écran pour tous les visiteurs ;
  chiffrement obsolète = trafic interceptable. *(§14.6)*
- **② Ce que ça apporte** : le certificat prouve l'identité du site, TLS 1.2/1.3 chiffre les échanges.
- **③ Comment on vérifie** : on établit une vraie connexion sécurisée comme le ferait un
  navigateur ; si le certificat est refusé, on va lire quand même le certificat pour dire
  **pourquoi** (expiré depuis N jours, auto-signé, mauvais domaine) au lieu d'un message générique.
- **④ ANSSI** : **R3** « Privilégier TLS 1.3 et accepter TLS 1.2 » — guide TLS **SDE-NT-35** ;
  **R1** « Mettre en œuvre TLS à l'état de l'art » — **ANSSI-PA-009**.

#### 3 — En-têtes de sécurité *(zoom retenu)*
- **① Problème** : injection de code (XSS), site piégé dans une fausse page (clickjacking),
  connexion rabattue en clair, fuite d'adresses internes. *(§14.7/8)*
- **② Ce que ça apporte** : chaque en-tête bloque une classe d'attaque précise.
- **③ Comment on vérifie** : on demande la page comme un navigateur et on inspecte les en-têtes de
  réponse ; si le site est mal configuré en HTTPS, on sait quand même l'auditer.
- **④ ANSSI** : **R2** (HSTS), **R14** (CSP), **R18** (X-Frame-Options), **R21** (Referrer-Policy)
  — **ANSSI-PA-009**. ⚠️ `nosniff` → **OWASP Secure Headers**.
- **Exemple massue** : **esgi.fr → 0/100**, les 5 en-têtes absents, vérifiable en direct.

#### 4 — Messagerie *(zoom retenu)*
- **① Problème** : les mails circulent en clair entre serveurs ; le serveur peut révéler son
  logiciel et sa version à un attaquant ; un serveur unique = plus d'emails pendant une panne.
  *(§14.9)*
- **② Ce que ça apporte** : le chiffrement du transport protège le contenu ; un serveur discret
  ne renseigne pas l'attaquant ; la redondance assure la continuité.
- **③ Comment on vérifie** : on se connecte au serveur de messagerie comme le ferait un autre
  serveur mail et on regarde s'il propose le chiffrement ; si l'hébergeur bloque cette connexion,
  **le critère est exclu du barème** au lieu d'être noté au hasard.
- **④ ANSSI** : **R42** (STARTTLS), **R44** (SPF), **R46+** (DKIM), **R48+** (DMARC), **R51**
  (disponibilité) — **ANSSI-PA-066**.
- **Bonus jury** : pourquoi **DKIM n'est pas vérifiable** à distance (§14.3) — maîtriser sa limite
  vaut mieux que la subir.

#### 5 — Subdomain takeover *(zoom retenu)*
- **① Problème** : un sous-domaine pointe encore vers un service cloud abandonné → un inconnu
  reprend l'adresse et publie ce qu'il veut au nom de l'entreprise, avec un certificat valide.
  *(§14.10)*
- **② Ce que ça apporte** : faire le ménage dans les entrées DNS oubliées.
- **③ Comment on vérifie** : on teste les sous-domaines les plus courants, on repère ceux qui
  renvoient vers un service tiers, puis on vérifie si la ressource est réellement **abandonnée**
  (page d'erreur caractéristique du service).
- **④ ⚠️ Pas d'ANSSI.** Référentiel : **can-i-take-over-xyz**. Lien indirect : principe de
  **surface d'exposition minimale**.

#### 6 — Expiration du domaine
- **① Problème** : un domaine non renouvelé est racheté par un tiers → le site **et les emails**
  de la PME lui appartiennent. *(§14.11)*
- **② Ce que ça apporte** : anticiper le renouvellement.
- **③ Comment on vérifie** : consultation du registre public des noms de domaine ; certains
  registres restreignent l'information (RGPD) → on le signale au lieu de deviner.
- **④ ANSSI** : **ANSSI-BP-038** — le guide décrit le risque (domaine racheté par un attaquant qui
  « fournit alors des données falsifiées ») ; **R1** (verrou registre), **R2** (registrar sécurisé).

#### 7 — OSINT / fuites de données
- **① Problème** : les identifiants d'employés circulent dans des fuites publiques ; un site
  compromis peut distribuer des malwares à l'insu du gérant. *(§14.12)*
- **② Ce que ça apporte** : savoir ce qu'un attaquant trouve sur vous **avant** lui.
- **③ Comment on vérifie** : croisement de trois bases publiques de renseignement (fuites de
  données, URLs malveillantes, listes noires).
- **④ ⚠️ Pas d'ANSSI.** Référentiels : **HIBP** et **URLhaus (abuse.ch)** — les mêmes sources que
  consultent les attaquants.

### 16.6 La démonstration (diapos 14-15, ~4 min 30)

Comprise **dans** les 20 minutes, donc chronométrée et répétée.

1. Lancer le scan sur un domaine préparé → commenter la progression pendant que ça tourne.
2. Page résultats : lire le score, déplier une analyse en avertissement, insister sur le
   **langage accessible** des recommandations (c'est la valeur du produit).
3. Poser **une** question à l'assistant IA (« par quoi je commence ? »).
4. Télécharger et montrer le **rapport PDF**.

**Vidéo de secours obligatoire** (consigne) : enregistrer ce scénario **avant** le jour J, l'avoir
en local (pas en streaming). Prévoir aussi un scan déjà en base pour rebondir sans réseau.

### 16.7 Règles de forme (jury de professionnels)

- **Numéro sur chaque diapo** (consigne explicite).
- **Une idée par diapo**, police ≥ 24 pt. La diapo appuie le discours, elle ne le remplace pas.
- **Zéro code à l'écran.** Des schémas, des captures d'interface, un extrait du rapport PDF.
- **Ne pas meubler** : mieux vaut 15 diapos utiles que 25 remplies.
- **Tenue professionnelle**, pas de baskets.
- **Répéter avec un chrono**, au moins deux fois en entier, démo comprise. Le dépassement est la
  faute la plus sanctionnée : à 20 min on vous coupe, et c'est la conclusion qui saute.
- **Garder les munitions pour les questions** : §12 (questions probables), §14 (le cours), §15
  (anecdotes, à raconter **sans jargon de code**), §17 (les références ANSSI exactes).

### Check-list avant la soutenance
- [ ] Demander (ou relire) **le barème** communiqué par l'école.
- [ ] Diapos **numérotées**, minimum 15, aucune capture de code.
- [ ] **Vidéo de la démo enregistrée** et testée en local.
- [ ] Backend à jour et testé le matin même ; un scan « intéressant » déjà en base.
- [ ] Domaines de démo répétés : un bon (cloudflare.com), un moyen (esgi.fr — en-têtes 0/100),
      badssl.com pour le certificat expiré.
- [ ] Attention à la faute de frappe cloud**fl**are.com pendant la démo 😉.
- [ ] Savoir dire ce qui **ne vient pas** de l'ANSSI (nosniff, takeover, OSINT) — §17.
- [ ] **Deux répétitions chronométrées** en entier, démo comprise.
- [ ] **Tenue professionnelle** préparée la veille.
- [ ] Relire §12, §14 et §17 la veille.

---

## 17. Traçabilité des référentiels — quelle recommandation ANSSI derrière chaque contrôle

> **À quoi ça sert :** si le jury demande « d'où sortent vos critères ? », on ne répond pas
> « de l'ANSSI » en vague : on cite le guide, sa **référence**, et le **numéro de recommandation**.
> Les 5 guides ci-dessous ont été vérifiés (référence, date, version) — les numéros R sont ceux
> des documents officiels.

### Les 5 guides ANSSI utilisés

| # | Guide | Référence | Date / version | Sert à |
|---|---|---|---|---|
| **G1** | Recommandations relatives à l'interconnexion d'un système d'information à Internet | **ANSSI-PA-066** | 19/06/2020, v3.0 | SPF, DKIM, DMARC, STARTTLS, DNSSEC messagerie |
| **G2** | Recommandations pour la mise en œuvre d'un site web : maîtriser les standards de sécurité côté navigateur | **ANSSI-PA-009** | 28/04/2021, v2.0 | HSTS, CSP, X-Frame-Options, Referrer-Policy |
| **G3** | Recommandations de sécurité relatives à TLS | **SDE-NT-35/ANSSI/SDE/NP** | 26/03/2020, v1.2 | Versions TLS, certificats |
| **G4** | Recommandations relatives aux architectures des services DNS | **ANSSI-PA-105** | 17/07/2024, v1.0 | DNSSEC |
| **G5** | Bonnes pratiques pour l'acquisition et l'exploitation de noms de domaine | **ANSSI-BP-038** | 10/11/2017, v1.3 | Cycle de vie du domaine, redondance DNS |

Liens (tous sur `cyber.gouv.fr` / `messervices.cyber.gouv.fr`) :
- G1 — [anssi-guide-passerelle_internet_securisee-v3.pdf](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-passerelle_internet_securisee-v3.pdf)
- G2 — [anssi-guide-recommandations_mise_en_oeuvre_site_web…-v2.0.pdf](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-recommandations_mise_en_oeuvre_site_web_maitriser_standards_securite_cote_navigateur-v2.0.pdf)
- G3 — [anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf)
- G4 — [anssi-guide-archi_services_dns-v1-0.pdf](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-archi_services_dns-v1-0.pdf)
- G5 — [guide_dns_fr_anssi_1.3.pdf](https://cyber.gouv.fr/documents/422/guide_dns_fr_anssi_1.3.pdf)

### Tableau de correspondance : chaque contrôle → sa source

| Notre contrôle | Module | Référentiel | Recommandation exacte |
|---|---|---|---|
| **SPF** valide | DNS | G1 | **R44** — « Configurer SPF pour les domaines de messagerie électronique de l'entité » (et R43 côté réception) |
| **DMARC** valide (`p=reject`) | DNS | G1 | **R48+** — « Configurer DMARC pour les domaines de messagerie électronique de l'entité » (et R47+ côté réception) |
| **DNSSEC** activé | DNS | G1 + G4 | G1 **R50+** — « Configurer DNSSEC pour les domaines de messagerie électronique de l'entité » ; G4 **R14** — « Activer DNSSEC sur le service DNS de résolution des noms de domaine Internet » (voir aussi G4 R11–R13 : analyse de risque, processus de gestion, supervision) |
| **MX** présents / redondance | DNS + Email | G5 **R6** — « Utiliser au moins deux serveurs faisant autorité » (esprit de redondance) ; G1 **R51** — « Prévoir des mesures de protection en disponibilité du service de messagerie » |
| **STARTTLS** sur le serveur SMTP | Email | G1 | **R42** — « Activer l'option STARTTLS sur les serveurs SMTP » (R42+ va plus loin avec REQUIRETLS) |
| **TLS 1.2 / 1.3** uniquement | SSL | G3 | **R3** — « Privilégier TLS 1.3 et accepter TLS 1.2 » (les versions antérieures sont à proscrire) |
| Certificat valide / non expiré | SSL | G3 | Chapitre certificats (R26 « Utiliser des clés de taille suffisante », R38 « Utiliser des certificats enregistrés par CT ») ; G2 **R1** — « Mettre en œuvre TLS à l'état de l'art » |
| **HSTS** | SSL + Headers | G2 | **R2** — « Mettre en œuvre HSTS » |
| **Content-Security-Policy** | Headers | G2 | **R14** — « Mettre en œuvre CSP par en-tête HTTP » (+ R13, R15, R16 sur les directives) |
| **X-Frame-Options** | Headers | G2 | **R18** — « Utiliser X-Frame-Options contre le clickjacking » (+ **R17** « Utiliser CSP contre le clickjacking ») |
| **Referrer-Policy** | Headers | G2 | **R21** — « Définir la stratégie de construction de l'en-tête Referer » |
| **X-Content-Type-Options: nosniff** | Headers | **OWASP uniquement** | Non couvert nommément par les guides ANSSI consultés → source : [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) |
| Expiration du nom de domaine | Expiration | G5 | Pas de numéro R dédié, mais le guide décrit explicitement le risque : un domaine non renouvelé avant son expiration peut être racheté par un attaquant qui « fournit alors des données falsifiées » ; voir aussi **R1** (verrou registre) et **R2** (registrar à authentification renforcée) |
| Sous-domaines orphelins (takeover) | Takeover | **Hors ANSSI** | Source : [can-i-take-over-xyz (EdOverflow)](https://github.com/EdOverflow/can-i-take-over-xyz) — projet de référence de la communauté sécurité offensive |
| Fuites de données / malware | OSINT | **Hors ANSSI** | Sources OSINT publiques : [HIBP](https://haveibeenpwned.com) et [URLhaus / abuse.ch](https://urlhaus.abuse.ch) |
| Bannière SMTP discrète | Email | **Bonne pratique générale** | Principe de réduction de la surface d'information (ne pas divulguer logiciel/version) — pas de recommandation ANSSI nominative sur la bannière SMTP |

### Ce qu'il faut savoir dire (et ne pas dire)

**À dire :** « Nos points de contrôle sont adossés à 5 guides ANSSI, référencés et datés — par
exemple, le test STARTTLS correspond à la recommandation R42 du guide ANSSI-PA-066 sur
l'interconnexion à Internet, et le test HSTS à la R2 du guide ANSSI-PA-009 sur les sites web. »

**Honnêteté intellectuelle (à assumer si on creuse) :** trois de nos contrôles **ne viennent pas
de l'ANSSI** et il faut le dire franchement plutôt que se faire prendre :
- `X-Content-Type-Options: nosniff` → OWASP Secure Headers ;
- le subdomain takeover → projet communautaire can-i-take-over-xyz ;
- l'OSINT (fuites, malware) → bases publiques HIBP/URLhaus.

**Et surtout (rappel du §3) :** l'ANSSI fournit les **points de contrôle**, jamais un **score sur
100**. Le barème (25 pts SPF, 30 pts DMARC…) et les seuils de sévérité sont **notre méthodologie**,
inspirée des principes d'audit (un constat repose sur une preuve → ce qui n'est pas observable est
exclu du barème). Ne jamais laisser croire que « le score est certifié ANSSI ».
