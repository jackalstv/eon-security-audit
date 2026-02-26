/**
 * ÉON - Frontend JavaScript
 * Gère les interactions avec l'API backend
 */

const API_BASE_URL = `http://${window.location.hostname}:8000/api/v1`;

// État de l'application
let currentScanId = null;

document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const domain = document.getElementById('domain').value.trim();
    const includeSubdomains = document.getElementById('includeSubdomains').checked;

    showLoading();

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                domain: domain,
                include_subdomains: includeSubdomains
            })
        });

        if (!response.ok) {
            const errData = await response.json();
            const msg = errData.detail?.[0]?.msg || errData.detail || 'Erreur lors du scan';
            showError(msg);
            return;
        }

        const data = await response.json();

        if (data.success) {
            currentScanId = data.scan_id;
            displayResults(data.result);
        } else {
            showError(data.error || 'Erreur lors du scan');
        }

    } catch (error) {
        console.error('Erreur:', error);
        showError('Impossible de se connecter au serveur. Vérifiez que le backend est lancé.');
    } finally {
        hideLoading();
    }
});

/**
 * Affiche les résultats du scan
 */
function displayResults(result) {
    document.getElementById('resultsSection').classList.remove('hidden');

    document.getElementById('overallScore').textContent = result.overall_score;
    document.getElementById('platformDetected').textContent = `Plateforme: ${result.platform}`;

    const modulesContainer = document.getElementById('modulesResults');
    modulesContainer.innerHTML = '';

    if (result.modules && result.modules.length > 0) {
        result.modules.forEach(module => {
            modulesContainer.innerHTML += createModuleCard(module);
        });
    } else {
        modulesContainer.innerHTML = `
            <div class="text-center py-8 text-purple-300">
                <p>Aucun module exécuté pour le moment.</p>
                <p class="text-sm mt-2">Le scan est en cours de développement.</p>
            </div>
        `;
    }

    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
}

/**
 * Crée une card pour un module
 */
function createModuleCard(module) {
    const severityColors = {
        critical: 'border-red-500 bg-red-950/30',
        high: 'border-orange-500 bg-orange-950/30',
        medium: 'border-yellow-500 bg-yellow-950/30',
        low: 'border-blue-500 bg-blue-950/30',
        info: 'border-purple-500 bg-purple-950/30'
    };

    const statusIcons = {
        success: '✅',
        warning: '⚠️',
        error: '❌',
        info: 'ℹ️'
    };

    const colorClass = severityColors[module.severity] || severityColors.info;
    const icon = statusIcons[module.status] || 'ℹ️';

    return `
        <div class="border ${colorClass} rounded-lg p-6 backdrop-blur-sm">
            <div class="flex items-start justify-between mb-4">
                <div>
                    <h4 class="text-lg font-semibold flex items-center gap-2">
                        ${icon} ${module.module_name}
                    </h4>
                    <p class="text-sm text-purple-300 mt-1">Score: ${module.score}/100</p>
                </div>
                <span class="px-3 py-1 rounded-full text-xs font-semibold ${getSeverityBadgeClass(module.severity)}">
                    ${module.severity.toUpperCase()}
                </span>
            </div>

            ${module.recommendations && module.recommendations.length > 0 ? `
                <div class="mt-4">
                    <p class="text-sm font-semibold mb-2 text-purple-200">Recommandations:</p>
                    <ul class="space-y-1 text-sm text-purple-300">
                        ${module.recommendations.map(rec => `<li>• ${rec}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        </div>
    `;
}

/**
 * Retourne la classe CSS pour le badge de sévérité
 */
function getSeverityBadgeClass(severity) {
    const classes = {
        critical: 'bg-red-600 text-white',
        high: 'bg-orange-600 text-white',
        medium: 'bg-yellow-600 text-black',
        low: 'bg-blue-600 text-white',
        info: 'bg-purple-600 text-white'
    };
    return classes[severity] || classes.info;
}

/**
 * Affiche l'état de chargement
 */
function showLoading() {
    document.getElementById('loadingState').classList.remove('hidden');
    document.getElementById('resultsSection').classList.add('hidden');
}

/**
 * Cache l'état de chargement
 */
function hideLoading() {
    document.getElementById('loadingState').classList.add('hidden');
}

/**
 * Affiche une erreur
 */
function showError(message) {
    // Nettoyer le préfixe pydantic "Value error, " si présent
    const cleanMessage = message.replace(/^Value error,\s*/i, '');
    alert(`Erreur: ${cleanMessage}`);
}

/**
 * Réinitialise le formulaire
 */
function resetForm() {
    document.getElementById('scanForm').reset();
    document.getElementById('resultsSection').classList.add('hidden');
    currentScanId = null;
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/**
 * Export PDF (à implémenter)
 */
function exportPDF() {
    if (!currentScanId) {
        alert('Aucun scan à exporter');
        return;
    }
    alert('Export PDF en cours de développement...');
    console.log('Export PDF pour scan:', currentScanId);
}

/**
 * Vérifier la connexion au backend au chargement
 */
window.addEventListener('DOMContentLoaded', async () => {
    try {
        const response = await fetch(`${API_BASE_URL.replace('/api/v1', '')}/health`);
        if (response.ok) {
            console.log('✅ Backend connecté');
        }
    } catch (error) {
        console.warn('⚠️ Backend non disponible:', error.message);
        console.log('💡 Lancez le backend avec: cd backend && python main.py');
    }
});