# Guide de démarrage - ÉON

## Installation

### Option 1 : Script automatique

```bash
chmod +x setup.sh
./setup.sh
```

### Option 2 : Manuel

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Lancement

### Terminal 1 - Backend

```bash
cd backend
source venv/bin/activate
python main.py
```

Serveur sur `http://localhost:8000`

### Terminal 2 - Frontend

```bash
cd frontend
python3 -m http.server 3000
```

Frontend sur `http://localhost:3000`

## Vérification

- Backend : http://localhost:8000/health doit retourner `{"status":"healthy"}`
- Docs API : http://localhost:8000/api/docs
- Frontend : http://localhost:3000

## Utilisation

1. Ouvrir http://localhost:3000
2. Entrer un domaine (ex: `google.com`)
3. Lancer l'audit
4. Télécharger le rapport PDF depuis la page de résultats

## Tests

```bash
cd backend
pytest tests/ -v
```

## Commandes utiles

```bash
# Activer venv
source backend/venv/bin/activate

# Lancer les tests
cd backend && pytest

# Reset DB
rm backend/eon.db
```

## Problèmes courants

### Port 8000 déjà utilisé
```bash
lsof -i :8000
kill -9 <PID>
```

### Erreur d'import Python
```bash
# Vérifier que venv est activé
which python

pip install -r requirements.txt --force-reinstall
```

### Frontend ne se connecte pas au backend
- Vérifier que le backend tourne sur http://localhost:8000
- Ouvrir la console du navigateur (F12) pour voir les erreurs
