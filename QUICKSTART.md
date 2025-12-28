# 🚀 Guide de Démarrage Rapide - ÉON

## Installation (5 minutes)

### Option 1 : Script automatique (recommandé)

```bash
cd eon
chmod +x setup.sh
./setup.sh
```

### Option 2 : Installation manuelle

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Éditer .env si besoin
nano .env
```

## Lancement du Projet

### Terminal 1 - Backend

```bash
cd backend
source venv/bin/activate
python main.py
```

Le serveur démarre sur `http://localhost:8000`

### Terminal 2 - Frontend

```bash
cd frontend
python3 -m http.server 3000
```

Le frontend est accessible sur `http://localhost:3000`

## Vérification

✅ Backend : http://localhost:8000/health doit retourner `{"status":"healthy"}`  
✅ API Docs : http://localhost:8000/api/docs (Swagger UI)  
✅ Frontend : http://localhost:3000

## Test Rapide

1. Ouvrir http://localhost:3000
2. Entrer un domaine (ex: `google.com`)
3. Cliquer sur "Démarrer l'Audit"
4. Observer les résultats (pour l'instant mockés)

## Prochaines Étapes

Maintenant que le squelette fonctionne, on va implémenter les modules un par un :

1. **Module 1 : Platform Detector** (4h)
2. **Module 2 : DNS Analyzer** (12h)
3. etc...

## Structure des Fichiers

```
eon/
├── backend/
│   ├── main.py              ← Point d'entrée
│   ├── config.py            ← Configuration
│   ├── requirements.txt     ← Dépendances
│   ├── api/
│   │   ├── routes.py        ← Endpoints REST
│   │   └── models.py        ← Validation Pydantic
│   ├── analyzers/           ← Modules d'audit (à implémenter)
│   ├── scoring/             ← Calcul scores (à implémenter)
│   └── database/            ← Models SQLAlchemy (à implémenter)
└── frontend/
    ├── index.html           ← Interface web
    └── app.js               ← Logique frontend
```

## Commandes Utiles

```bash
# Activer venv
source backend/venv/bin/activate

# Désactiver venv
deactivate

# Lancer tests
cd backend
pytest

# Voir les logs du serveur
# Les logs s'affichent directement dans le terminal

# Nettoyer la DB (reset)
rm backend/eon.db
```

## Troubleshooting

### Port 8000 déjà utilisé
```bash
# Trouver le processus
lsof -i :8000
# Tuer le processus
kill -9 <PID>
```

### Erreur d'import Python
```bash
# Vérifier que venv est activé
which python  # doit pointer vers backend/venv/bin/python

# Réinstaller les dépendances
pip install -r requirements.txt --force-reinstall
```

### Frontend ne se connecte pas au backend
- Vérifier que le backend tourne sur http://localhost:8000
- Vérifier les CORS dans `config.py`
- Ouvrir la console du navigateur (F12) pour voir les erreurs

## Next Steps

📌 **Semaine 1-2** : Implémenter Platform Detector + DNS Analyzer  
📌 **Semaine 3-4** : SSL + Headers + Email  
📌 **Semaine 5-6** : Subdomain + OSINT + Expiration

Bon code ! 🔥
