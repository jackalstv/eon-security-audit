# ÉON - Outil d'Audit Sécurité TPE

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-teal)

Outil web professionnel d'audit de sécurité pour TPE/PME, permettant d'évaluer automatiquement la posture de sécurité d'un domaine via des scans passifs (100% légaux) et de générer un rapport actionnable.

## Tableau des fonctionnalités

Audit de sécurité passif pour TPE/PME · 9 modules · Score global /100

| # | Module | Ce que ça fait | Auteur | Statut |
|---|--------|----------------|--------|--------|
| **Modules implémentés** | | | | |
| 1 | **Platform Detector** `platform_detector.py` | Identifie la technologie du site (Shopify, WordPress, Wix…) par analyse du HTML. Contextualise l'ensemble de l'audit. | André |  Fait |
| 2 | **DNS Security** `dns_analyzer.py` | Vérifie SPF, DMARC, DNSSEC et MX. Protège contre l'usurpation de domaine et le phishing. | André |  Fait |
| 3 | **SSL/TLS Security** `ssl_analyzer.py` | Analyse le certificat HTTPS (validité, expiration), la version TLS et la présence du header HSTS. | André |  Fait |
| 4 | **Security Headers** `security_headers_analyzer.py` | Vérifie les headers de sécurité OWASP/ANSSI : CSP, X-Frame-Options, HSTS, Referrer-Policy, X-Content-Type-Options. | Théo |  Fait |
| 5 | **Email Security** `email_analyzer.py` | Teste la configuration du serveur mail : enregistrements MX, redondance, chiffrement STARTTLS, bannière SMTP. | Théo |  Fait |
| 6 | **Subdomain Takeover** `subdomain_takeover_analyzer.py` | Détecte les sous-domaines pointant vers des services abandonnés, potentiellement récupérables par un attaquant. | André |  Fait |
| **Modules en cours / à implémenter** | | | | |
| 7 | **Domain Expiration** `domain_expiration.py` | Interroge le WHOIS pour vérifier la date d'expiration du domaine. Alerte si renouvellement urgent (<30 jours). | Théo | 🔧 WIP |
| 8 | **OSINT Breaches** `osint_breaches.py` | Interroge Have I Been Pwned pour détecter si des emails du domaine ont fuité dans des bases de données piratées. | Théo | 🔧 WIP |
| 9 | **Questionnaire Posture** `questionnaire.py` | Questionnaire manuel sur les pratiques humaines : MFA, sauvegardes, formation phishing, mises à jour, gestion des accès. | Omar | 🔧 WIP |
| **Infrastructure & fonctionnalités transverses** | | | | |
| — | **Base de données** PostgreSQL | Persistance des résultats de scan. Actuellement en mémoire vive — nécessaire pour l'historique et les exports. | Omar | 🔧 WIP |
| — | **Export PDF** Rapport client | Génère un rapport structuré (scores, recommandations priorisées, date) exportable pour client ou assureur. | Omar | 🔧 WIP |
| — | **Historique des scans** Suivi temporel | Conserve les scans passés pour mesurer l'évolution du score dans le temps et détecter les régressions. | Omar | 🔧 WIP |

> Futur : intégration d'un Chatbot pour que le client puisse comprendre les scores et recommandations à appliquer.

##  Installation Rapide

### Prérequis
- Python 3.11+
- pip
- Git

### Setup Backend

```bash
# Cloner le repository
git clone <url-du-repo>
cd eon

# Créer l'environnement virtuel
cd backend
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Installer les dépendances
pip install -r requirements.txt

# Configurer les variables d'environnement
cp .env.example .env
# Éditer .env et ajouter vos API keys

# Lancer le serveur
python main.py
```

Le serveur démarre sur `http://localhost:8000`

Documentation API : `http://localhost:8000/api/docs`

### Setup Frontend

```bash
cd frontend
# Ouvrir index.html dans un navigateur
# ou utiliser un serveur HTTP simple :
python3 -m http.server 3000
```

## 📁 Structure du Projet

```
eon/
├── backend/           # API FastAPI
│   ├── main.py       # Point d'entrée
│   ├── config.py     # Configuration
│   ├── api/          # Routes & modèles
│   ├── analyzers/    # Modules d'audit
│   ├── scoring/      # Calcul scores
│   ├── database/     # SQLAlchemy models
│   ├── reports/      # Export PDF
│   └── tests/        # Tests unitaires
└── frontend/         # Interface web
    ├── index.html
    ├── app.js
    └── styles.css
```

## 🛠️ Technologies

- **Backend**: Python 3.11, FastAPI, SQLAlchemy
- **Database**: SQLite (dev) → PostgreSQL (prod)
- **Frontend**: HTML5, Tailwind CSS, Vanilla JS
- **Libs Sécu**: dnspython, checkdmarc, cryptography
- **PDF**: ReportLab
- **Deploy**: Railway (backend) + Vercel (frontend)

## 📊 Roadmap

- [x] Phase 1: MVP Fonctionnel (S1-12)
- [ ] Phase 2: Stabilisation & Production (S13-20)
- [ ] Phase 3: Améliorations UX (S21-24)
- [ ] Phase 4: Finalisation (S25-28)

## 👥 Équipe

Projet M1 Cybersécurité - ESGI France  
Durée : 7 mois (travail week-end uniquement)

## 📝 License

Projet académique - ESGI 2024-2025

## 🔗 Liens Utiles

- [Documentation API](http://localhost:8000/api/docs)
- [Rapport de projet](docs/rapport.pdf) _(à venir)_
- [Présentation](docs/slides.pdf) _(à venir)_
