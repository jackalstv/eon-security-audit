# ÉON - Outil d'Audit Sécurité TPE/PME

Outil web d'audit de sécurité pour TPE/PME, permettant d'évaluer automatiquement la posture de sécurité d'un domaine via des scans passifs (100% légaux) et de générer un rapport PDF.

L'application est déployée sur un VPS Oracle Cloud. Le backend tourne dans Docker, le frontend est servi par nginx.

## Modules d'audit

| # | Module | Ce que ça fait | Auteur |
|---|--------|----------------|--------|
| 1 | Platform Detector | Identifie la technologie du site (Shopify, WordPress, Wix…) par analyse du HTML | André |
| 2 | DNS Security | Vérifie SPF, DMARC, DNSSEC et MX. Protège contre l'usurpation de domaine | André |
| 3 | SSL/TLS Security | Analyse le certificat HTTPS (validité, expiration), la version TLS et HSTS | André |
| 4 | Security Headers | Vérifie les headers de sécurité OWASP/ANSSI : CSP, X-Frame-Options, HSTS, etc. | Théo |
| 5 | Email Security | Teste la configuration mail : MX, redondance, STARTTLS, bannière SMTP | Théo |
| 6 | Subdomain Takeover | Détecte les sous-domaines pointant vers des services abandonnés | André |
| 7 | Domain Expiration | Interroge le WHOIS pour vérifier la date d'expiration du domaine | Théo |
| 8 | OSINT Breaches | Interroge Have I Been Pwned pour détecter des fuites liées au domaine | Théo |

## Déploiement (production)

L'infrastructure est sur un VPS Oracle Cloud avec Docker.

### Déployer une modification backend

```bash
# Sur le VPS
docker compose build eon-backend && docker compose up -d eon-backend
```

### Déployer une modification frontend

```bash
# Sur le VPS — nginx sert les fichiers statiques directement
git pull
```

### Se connecter au VPS

```bash
ssh -i "chemin/vers/ssh-key.key" ubuntu@<ip-vps>
cd /home/ubuntu/eon/
```

## Développement local

### Prérequis
- Python 3.11+
- Git

### Backend

```bash
cd backend

python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

pip install -r requirements.txt

cp .env.example .env
# Ajouter les API keys dans .env si besoin

python main.py
```

API disponible sur `http://localhost:8000` — docs : `http://localhost:8000/api/docs`

### Frontend

Le frontend est un SPA en HTML/CSS/JS vanilla. En local, ouvrir `frontend/index.html` directement dans le navigateur ou lancer un serveur simple :

```bash
cd frontend
python3 -m http.server 3000
```

## Tests

```bash
cd backend
pytest tests/ -v
```

Les tests unitaires utilisent des mocks (pas d'appel réseau). Les tests d'intégration dans `test_integration.py` font de vrais appels vers des domaines connus (google.com, cloudflare.com).

## Structure du projet

```
eon-security-audit/
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── database.py
│   ├── db_models.py
│   ├── pdf_report.py
│   ├── Dockerfile
│   ├── api/
│   │   ├── routes.py
│   │   ├── chat.py
│   │   └── models.py
│   ├── analyzers/
│   │   ├── dns_analyzer.py
│   │   ├── ssl_analyzer.py
│   │   ├── security_headers_analyzer.py
│   │   ├── email_analyzer.py
│   │   ├── subdomain_takeover_analyzer.py
│   │   ├── domain_expiration.py
│   │   ├── osint_breaches.py
│   │   └── platform_detector.py
│   ├── templates/
│   │   └── report.html.j2
│   └── tests/
│       ├── test_dns_analyzer.py
│       ├── test_email_analyzer.py
│       ├── test_ssl_analyzer.py
│       ├── test_security_headers.py
│       ├── test_subdomain_takeover.py
│       ├── test_domain_expiration.py
│       ├── test_osint_breaches.py
│       └── test_integration.py
└── frontend/
    ├── index.html
    ├── app.js
    └── styles.css
```

## Technologies

- **Backend** : Python 3.11, FastAPI, SQLAlchemy, PostgreSQL
- **Frontend** : HTML5, CSS, Vanilla JS
- **Libs sécurité** : dnspython, checkdmarc, python-whois
- **PDF** : WeasyPrint + Jinja2
- **IA** : API Anthropic (assistant chat intégré)
- **Infrastructure** : VPS Oracle Cloud, Docker, nginx

## Améliorations possibles

- **Gestion des dépendances avec Poetry** : le projet utilise actuellement `pip + requirements.txt`. Poetry permettrait de distinguer les dépendances de production et de développement (par exemple, pytest ne serait installé qu'en dev), et de générer un fichier `poetry.lock` qui fige les versions exactes de chaque bibliothèque, garantissant un environnement identique entre les développeurs et le serveur de production.

## Équipe

Projet M1 Cybersécurité - ESGI 2024-2025
