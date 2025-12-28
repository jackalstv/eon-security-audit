#!/bin/bash

echo "🚀 Setup ÉON - Audit Sécurité TPE"
echo "================================="
echo ""

# Couleurs
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Vérifier Python
echo -e "${BLUE}[1/5] Vérification de Python...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}⚠️  Python 3 non trouvé. Installez Python 3.11+ et relancez ce script.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo -e "${GREEN}✓ Python $PYTHON_VERSION détecté${NC}"
echo ""

# Créer l'environnement virtuel
echo -e "${BLUE}[2/5] Création de l'environnement virtuel...${NC}"
cd backend
if [ -d "venv" ]; then
    echo -e "${YELLOW}⚠️  venv existe déjà, on le réutilise${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}✓ Environnement virtuel créé${NC}"
fi
echo ""

# Activer venv et installer dépendances
echo -e "${BLUE}[3/5] Installation des dépendances...${NC}"
source venv/bin/activate

pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements.txt

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Dépendances installées${NC}"
else
    echo -e "${YELLOW}⚠️  Erreur lors de l'installation des dépendances${NC}"
    exit 1
fi
echo ""

# Créer fichier .env si inexistant
echo -e "${BLUE}[4/5] Configuration de l'environnement...${NC}"
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo -e "${GREEN}✓ Fichier .env créé (pensez à configurer vos API keys)${NC}"
else
    echo -e "${YELLOW}⚠️  .env existe déjà, non modifié${NC}"
fi
echo ""

# Initialiser la base de données
echo -e "${BLUE}[5/5] Initialisation de la base de données...${NC}"
python3 -c "from database.models import Base; from sqlalchemy import create_engine; engine = create_engine('sqlite:///eon.db'); Base.metadata.create_all(engine)" 2>/dev/null || echo -e "${YELLOW}⚠️  DB sera créée au premier lancement${NC}"
echo ""

echo -e "${GREEN}=================================${NC}"
echo -e "${GREEN}✅ Setup terminé avec succès!${NC}"
echo -e "${GREEN}=================================${NC}"
echo ""
echo "📝 Prochaines étapes:"
echo ""
echo "1. Activer l'environnement virtuel:"
echo -e "   ${BLUE}cd backend && source venv/bin/activate${NC}"
echo ""
echo "2. Lancer le backend:"
echo -e "   ${BLUE}python main.py${NC}"
echo ""
echo "3. Dans un autre terminal, lancer le frontend:"
echo -e "   ${BLUE}cd frontend && python3 -m http.server 3000${NC}"
echo ""
echo "4. Ouvrir votre navigateur:"
echo -e "   ${BLUE}http://localhost:3000${NC}"
echo ""
echo "📚 Documentation API: http://localhost:8000/api/docs"
echo ""
