import checkdmarc
from api.models import ModuleResult, SeverityLevel

def analyze_dns(domain: str) -> ModuleResult:
    try:
        result = checkdmarc.check_domains([domain])
        
        # Initialiser le score
        score = 0
        details = {}
        recommendations = []
        
        # 1. Vérifier SPF (25 points)
        if result.get('spf', {}).get('valid'):
            score += 25
            details['spf'] = 'valid'
        else:
            details['spf'] = 'invalid ou manquant'
            recommendations.append("Configurer un enregistrement SPF")
        
        # 2. Vérifier DMARC (30 points)
        if result.get('dmarc', {}).get('valid'):
            score += 30
            details['dmarc'] = result['dmarc'].get('record', 'configured')
        else:
            details['dmarc'] = 'manquant'
            recommendations.append("Configurer DMARC avec politique p=quarantine minimum")
        
        # 3. Vérifier DNSSEC (20 points)
        if result.get('dnssec'):
            score += 20
            details['dnssec'] = 'activé'
        else:
            details['dnssec'] = 'désactivé'
            recommendations.append("Activer DNSSEC pour protéger contre le cache poisoning")
        
        # 4. Vérifier MX (25 points)
        if result.get('mx', {}).get('hosts'):
            score += 25
            details['mx'] = f"{len(result['mx']['hosts'])} serveur(s) configuré(s)"
        else:
            details['mx'] = 'non configuré'
            recommendations.append("Configurer les enregistrements MX")

        # Déterminer le status et la sévérité selon le score
        if score >= 80:
            status = "success"
            severity = SeverityLevel.LOW
        elif score >= 50:
            status = "warning"
            severity = SeverityLevel.MEDIUM
        elif score >= 30:
            status = "warning"
            severity = SeverityLevel.HIGH
        else:
            status = "error"
            severity = SeverityLevel.CRITICAL
        
        return ModuleResult(
            module_name="DNS Security",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations
        )
    
    except Exception as e:
        return ModuleResult(
            module_name="DNS Security",
            status="error",
            severity=SeverityLevel.HIGH,
            score=0,
            details={"error": str(e)},
            recommendations=["Vérifier la configuration DNS du domaine"]
        )
