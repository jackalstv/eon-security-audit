# 🔀 Guide Git - Collaboration ÉON

## Setup Initial GitHub

### 1. Créer le Repository

```bash
# Sur GitHub, créer un nouveau repo "eon-security-audit"
# Ensuite, sur ta machine :

cd eon
git init
git add .
git commit -m "🎉 Initial commit - Architecture ÉON"
git branch -M main
git remote add origin git@github.com:TON_USERNAME/eon-security-audit.git
git push -u origin main
```

### 2. Inviter ton Binôme

1. Sur GitHub → Settings → Collaborators
2. Ajouter ton binôme avec accès Write

---

## Workflow Git (Recommandé)

### Branches

```
main
├── dev                    # Branche de développement
│   ├── feature/module-1   # Platform Detector
│   ├── feature/module-2   # DNS Analyzer
│   ├── feature/frontend   # Améliorations UI
│   └── fix/bug-xxx        # Corrections de bugs
```

### Règles
- **main** : Code stable, testé, fonctionnel uniquement
- **dev** : Intégration des features avant merge vers main
- **feature/*** : Une branche par module/fonctionnalité
- **fix/*** : Corrections de bugs

---

## Commandes Essentielles

### Démarrer une Nouvelle Feature

```bash
# Se mettre à jour
git checkout dev
git pull origin dev

# Créer une branche
git checkout -b feature/platform-detector

# Travailler...
# (coder, tester)

# Commit réguliers
git add backend/analyzers/platform_detector.py
git commit -m "✨ Add platform detection for Shopify"

git add backend/analyzers/platform_detector.py
git commit -m "✨ Add Wix detection"

# Push
git push origin feature/platform-detector
```

### Merge vers Dev

```bash
# Après avoir push ta feature
# Sur GitHub : Create Pull Request
# feature/platform-detector → dev

# Ou en ligne de commande :
git checkout dev
git pull origin dev
git merge feature/platform-detector
git push origin dev
```

### Merge vers Main (Release)

```bash
# Seulement quand la feature est 100% testée
git checkout main
git pull origin main
git merge dev
git tag -a v0.1.0 -m "Module 1: Platform Detector"
git push origin main --tags
```

---

## Convention de Commits

Utiliser des préfixes clairs :

```
✨ feat: Nouvelle fonctionnalité
🐛 fix: Correction de bug
📝 docs: Documentation
🎨 style: Formatage, pas de changement de code
♻️ refactor: Refactoring
✅ test: Ajout/modification de tests
🚀 deploy: Déploiement
🔧 chore: Maintenance, configuration
```

**Exemples** :
```bash
git commit -m "✨ feat: Add DNS analyzer with SPF/DKIM validation"
git commit -m "🐛 fix: Handle DNS timeout errors gracefully"
git commit -m "📝 docs: Add DNS module documentation"
git commit -m "🎨 style: Format frontend with Prettier"
git commit -m "♻️ refactor: Simplify platform detection logic"
git commit -m "✅ test: Add unit tests for DNS analyzer"
```

---

## Résolution de Conflits

### Si tu as un conflit :

```bash
# Essayer de merge
git pull origin dev
# → CONFLICT!

# Ouvrir les fichiers en conflit
# Chercher les marqueurs <<<<<< ====== >>>>>>

# Éditer pour résoudre
nano backend/analyzers/dns_analyzer.py

# Marquer comme résolu
git add backend/analyzers/dns_analyzer.py
git commit -m "🔀 merge: Resolve conflict in DNS analyzer"
git push origin dev
```

---

## Workflow Binôme Recommandé

### Option A : Répartition par Module

**Personne 1** (toi ?) :
- Semaines 1-2 : Platform Detector + DNS Analyzer (backend)
- Semaines 3-4 : SSL + Headers (backend)
- Semaines 5-6 : Subdomain + OSINT (backend)

**Personne 2** :
- Semaines 1-2 : Frontend formulaire + Dashboard
- Semaines 3-4 : Email + Domain Expiration (backend)
- Semaines 5-6 : Frontend affichage résultats + UX

### Option B : Full-Stack par Sprint

**Sprint 1 (S1-2)** :
- Personne 1 : Module 1-2 (backend)
- Personne 2 : Frontend + intégration

**Sprint 2 (S3-4)** :
- Inversé

---

## Synchronisation Quotidienne

### Avant de commencer à coder :

```bash
git checkout dev
git pull origin dev
git checkout feature/ma-feature
git merge dev  # Récupérer les derniers changements
```

### Avant de finir la journée :

```bash
git add .
git commit -m "🚧 WIP: Progress on DNS analyzer"
git push origin feature/ma-feature
```

---

## Commandes d'Urgence

### Annuler le dernier commit (pas encore push)

```bash
git reset --soft HEAD~1  # Garde les modifications
# ou
git reset --hard HEAD~1  # Supprime tout
```

### Annuler un push (DANGEREUX)

```bash
git revert <commit-hash>
git push origin dev
```

### Récupérer un fichier supprimé

```bash
git checkout HEAD -- fichier-supprime.py
```

### Stash (mettre de côté temporairement)

```bash
# Mettre de côté
git stash

# Récupérer
git stash pop
```

---

## .gitignore Déjà Configuré

Le `.gitignore` exclut automatiquement :
- `venv/` (environnement virtuel)
- `*.db` (base de données locale)
- `.env` (secrets)
- `__pycache__/` (cache Python)
- `.vscode/`, `.idea/` (configs IDE)

---

## Bonnes Pratiques

✅ **Commit souvent** (petit commits atomiques)  
✅ **Pull avant de Push**  
✅ **Messages clairs** (utiliser les emojis conventionnels)  
✅ **Tester avant merge**  
✅ **Communiquer** (Discord/Slack pour coordination)  
✅ **Code review** (vérifier les PR du binôme)

❌ **Ne jamais** commit de secrets (.env, API keys)  
❌ **Ne jamais** push directement sur main sans tests  
❌ **Ne jamais** force push sur des branches partagées  

---

## Exemple de Workflow Semaine 1

```bash
# Lundi
git checkout -b feature/platform-detector
# Coder Platform Detector
git add backend/analyzers/platform_detector.py
git commit -m "✨ feat: Add Shopify detection"
git push origin feature/platform-detector

# Mercredi
# Continuer Platform Detector
git add backend/analyzers/platform_detector.py
git commit -m "✨ feat: Add Wix and WordPress detection"
git push origin feature/platform-detector

# Vendredi
# Tests
git add backend/tests/test_platform_detector.py
git commit -m "✅ test: Add platform detector unit tests"
git push origin feature/platform-detector

# Pull Request vers dev
# → Sur GitHub : Create PR
# → Binôme review → Merge
```

---

## Commandes Cheat Sheet

```bash
# Status
git status
git log --oneline --graph

# Branches
git branch              # Lister
git checkout -b xxx     # Créer et switcher
git checkout xxx        # Switcher
git branch -d xxx       # Supprimer

# Sync
git pull origin dev
git push origin feature

# Commit
git add fichier.py
git commit -m "message"
git commit -am "message"  # Add + commit fichiers modifiés

# Undo
git reset HEAD fichier.py    # Unstage
git checkout -- fichier.py   # Discard changes
git revert <hash>            # Revert commit

# Stash
git stash
git stash list
git stash pop
git stash drop
```

---

**Setup Git** :
```bash
git config --global user.name "Andre"
git config --global user.email "ton@email.fr"
```

Bon workflow ! 🚀
