import checkdmarc
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from api.models import ModuleResult, SeverityLevel


def _fallback_dns_check(domain: str) -> dict:
    """Vérification DNS basique via dnspython quand checkdmarc timeout."""
    result = {'spf': {'valid': False}, 'dmarc': {'valid': False, 'record': None}, 'dnssec': False, 'mx': {'hosts': []}}
    try:
        txts = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        for r in txts:
            if 'v=spf1' in str(r).lower():
                result['spf']['valid'] = True
    except Exception:
        pass
    try:
        dmrcs = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5)
        for r in dmrcs:
            if 'v=dmarc1' in str(r).lower():
                result['dmarc']['valid'] = True
                result['dmarc']['record'] = str(r).strip('"')
    except Exception:
        pass
    try:
        mxs = dns.resolver.resolve(domain, 'MX', lifetime=5)
        result['mx']['hosts'] = [str(mx.exchange).rstrip('.') for mx in mxs]
    except Exception:
        pass
    return result


def analyze_dns(domain: str) -> ModuleResult:
    try:
        executor = ThreadPoolExecutor(max_workers=1)
        future = executor.submit(checkdmarc.check_domains, [domain])
        try:
            result = future.result(timeout=35)
        except FuturesTimeoutError:
            executor.shutdown(wait=False)
            result = _fallback_dns_check(domain)
        executor.shutdown(wait=False)
        
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
                "Connectez-vous à l'interface où vous avez acheté votre nom de domaine (OVH, Gandi, Namecheap…) "
                "et ajoutez un enregistrement SPF, ou demandez à votre prestataire informatique de le faire."
            )

        # 2. Vérifier DMARC (30 points)
        if result.get('dmarc', {}).get('valid'):
            score += 30
            dmarc_record = result['dmarc'].get('record', 'configured')
            details['dmarc'] = dmarc_record
            if isinstance(dmarc_record, str) and 'p=quarantine' in dmarc_record.lower():
                recommendations.append(
                    "Votre protection anti-usurpation (DMARC) est active mais en mode 'quarantine' : "
                    "les emails frauduleux envoyés en votre nom sont renvoyés en spam, mais pas bloqués. "
                    "Pour une protection maximale, demandez à votre prestataire informatique de passer à p=reject, "
                    "qui bloque définitivement toute tentative d'usurpation de votre identité."
                )
        else:
            details['dmarc'] = 'manquant'
            recommendations.append(
                "Sans DMARC, vous ne pouvez pas détecter ni bloquer les usurpations de votre identité par email. "
                "Des cybercriminels peuvent lancer des campagnes de phishing ciblant vos clients en se faisant passer pour vous. "
                "Connectez-vous à l'interface de gestion de votre nom de domaine (OVH, Gandi…) "
                "pour ajouter un enregistrement DMARC, ou demandez à votre prestataire informatique."
            )

        # 3. Vérifier DNSSEC (20 points)
        if result.get('dnssec'):
            score += 20
            details['dnssec'] = 'activé'
        else:
            details['dnssec'] = 'désactivé'
            recommendations.append(
                "Sans DNSSEC, un attaquant pourrait rediriger vos visiteurs vers un faux site à votre place "
                "sans qu'ils ne s'en aperçoivent. "
                "Connectez-vous à l'interface de gestion de votre nom de domaine (OVH, Gandi…) "
                "et activez DNSSEC, ou demandez à votre prestataire informatique de le faire."
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
