# ÉON - Outil d'Audit Sécurité TPE

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-teal)

Outil web professionnel d'audit de sécurité pour TPE/PME, permettant d'évaluer automatiquement la posture de sécurité d'un domaine via des scans passifs (100% légaux) et de générer un rapport actionnable.

## 📋 Fonctionnalités

### 9 Modules d'Audit Passif
1. **Détection de plateforme** - Shopify, Wix, WordPress, auto-hébergé
2. **DNS Security** - SPF, DKIM, DMARC, DNSSEC
3. **Email Security** - Configuration MX, anti-spam
4. **SSL/TLS** - Certificats, HSTS, expiration
5. **Security Headers** - CSP, X-Frame-Options, etc.
6. **Domain Expiration** - Alerte sur expiration domaine
7. **Subdomain Takeover** - Détection sous-domaines vulnérables
8. **OSINT Breaches** - Vérification fuites de données (HIBP)
9. **Questionnaire Posture** - MFA, backups, formation

### Scoring & Recommandations
- Score global /100
- Priorisation des recommandations
- Export PDF professionnel
- Historique avec évolution temporelle

## 🚀 Installation Rapide

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
