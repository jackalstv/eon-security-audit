# Guide Git - Collaboration ÉON

## Setup initial

```bash
git clone <url-du-repo>
cd eon-security-audit
git checkout -b feature/ma-feature
```

## Workflow

### Branches

```
main              # code stable uniquement
feature/xxx       # une branche par fonctionnalité
fix/xxx           # corrections de bugs
```

### Démarrer une feature

```bash
git checkout main
git pull origin main
git checkout -b feature/dns-analyzer

# coder, tester...

git add backend/analyzers/dns_analyzer.py
git commit -m "Add DNS analyzer with SPF and DMARC validation"
git push origin feature/dns-analyzer
```

### Merge vers main

Créer une Pull Request sur GitHub : `feature/xxx → main`

---

## Convention de commits

Messages courts et clairs, en anglais ou français :

```bash
git commit -m "Add SPF validation in DNS analyzer"
git commit -m "Fix DNS timeout handling"
git commit -m "Add unit tests for email analyzer"
git commit -m "Update README with deploy instructions"
```

---

## Résolution de conflits

```bash
git pull origin main
# -> CONFLICT

# Ouvrir le fichier en conflit, chercher les marqueurs <<<<<<
# Résoudre manuellement, puis :
git add fichier.py
git commit -m "Resolve merge conflict"
```

---

## Commandes utiles

```bash
# Status et historique
git status
git log --oneline

# Branches
git branch
git checkout -b feature/xxx
git checkout main
git branch -d feature/xxx

# Sync
git pull origin main
git push origin feature/xxx

# Annuler le dernier commit (pas encore push)
git reset --soft HEAD~1

# Stash
git stash
git stash pop

# Récupérer un fichier supprimé
git checkout HEAD -- fichier.py
```

---

## Avant chaque session

```bash
git checkout main
git pull origin main
git checkout feature/ma-feature
git merge main
```

## En fin de journée

```bash
git add .
git commit -m "WIP: progress on DNS analyzer"
git push origin feature/ma-feature
```
