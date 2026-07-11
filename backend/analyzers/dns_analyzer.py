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
            recommendations.append(
                "Sans protection SPF, n'importe qui peut envoyer des emails qui semblent venir de votre domaine. "
                "Vos clients pourraient recevoir des arnaques en votre nom sans que vous le sachiez. "
                "Contactez votre hébergeur DNS ou votre registrar (OVH, Gandi…) pour configurer l'enregistrement SPF."
            )

        # 2. Vérifier DMARC (30 points)
        if result.get('dmarc', {}).get('valid'):
            score += 30
            details['dmarc'] = result['dmarc'].get('record', 'configured')
        else:
            details['dmarc'] = 'manquant'
            recommendations.append(
                "Sans DMARC, vous ne pouvez pas détecter ni bloquer les usurpations de votre identité par email. "
                "Des cybercriminels peuvent lancer des campagnes de phishing ciblant vos clients en se faisant passer pour vous. "
                "Demandez à votre hébergeur de mettre en place DMARC."
            )

        # 3. Vérifier DNSSEC (20 points)
        if result.get('dnssec'):
            score += 20
            details['dnssec'] = 'activé'
        else:
            details['dnssec'] = 'désactivé'
            recommendations.append(
                "Sans DNSSEC, un attaquant pourrait rediriger vos visiteurs vers un faux site à votre place "
                "sans qu'ils ne s'en aperçoivent (vos visiteurs croiraient être sur votre site). "
                "Contactez votre registrar (OVH, Cloudflare, Gandi…) pour activer DNSSEC."
            )

        # 4. Vérifier MX (25 points)
        if result.get('mx', {}).get('hosts'):
            score += 25
            details['mx'] = f"{len(result['mx']['hosts'])} serveur(s) configuré(s)"
        else:
            details['mx'] = 'non configuré'
            recommendations.append(
                "Votre domaine n'est pas configuré pour recevoir des emails. "
                "Tous les messages envoyés à une adresse @votredomaine seront rejetés ou perdus. "
                "Contactez votre hébergeur pour configurer la messagerie."
            )

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
