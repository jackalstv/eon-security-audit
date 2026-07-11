import ssl
import socket
import datetime
import requests
from api.models import ModuleResult, SeverityLevel

def analyze_ssl(domain: str) -> ModuleResult:
    """Analyse la configuration SSL/TLS d'un domaine"""
    try:
        score = 0
        details = {}
        recommendations = []
        
        # 1. Récupérer le certificat SSL et vérifier TLS
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # 4. Vérifier la version TLS (doit être ici, dans le with)
                tls_version = ssock.version()
                details['tls_version'] = tls_version
                if tls_version in ['TLSv1.2', 'TLSv1.3']:
                    score += 30
                    details['tls_status'] = 'Sécurisé'
                else:
                    details['tls_status'] = 'Version obsolète'
                    recommendations.append(
                        f"Votre site utilise un protocole de chiffrement dépassé ({tls_version}) "
                        "qui peut être contourné par des pirates. Les données échangées avec vos visiteurs "
                        "ne sont pas correctement protégées. "
                        "Contactez votre hébergeur ou prestataire technique pour mettre à jour la configuration TLS (version 1.2 minimum requise)."
                    )
        
        # 2. Vérifier la date d'expiration
        expiry_date_str = cert['notAfter']
        expiry_date = datetime.datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
        days_remaining = (expiry_date - datetime.datetime.now()).days
        
        if days_remaining > 30:
            score += 40
            details['certificate'] = f'Valide (expire dans {days_remaining} jours)'
        elif days_remaining > 0:
            score += 20
            details['certificate'] = f'Expire bientôt ({days_remaining} jours)'
            recommendations.append(
                f"Votre certificat de sécurité expire dans {days_remaining} jours. "
                "Sans renouvellement, votre site affichera une alerte de sécurité à tous vos visiteurs, "
                "ce qui nuira à votre crédibilité. Contactez votre hébergeur pour le renouveler."
            )
        else:
            details['certificate'] = 'EXPIRÉ'
            recommendations.append(
                "URGENT : Votre certificat de sécurité est expiré. Votre site affiche actuellement "
                "une alerte de danger à tous vos visiteurs, qui ne peuvent plus y accéder sereinement. "
                "Contactez votre hébergeur immédiatement pour renouveler le certificat."
            )
        
        # 3. Vérifier HSTS
        try:
            response = requests.get(f"https://{domain}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if 'Strict-Transport-Security' in response.headers:
                score += 30
                hsts_value = response.headers['Strict-Transport-Security']
                details['hsts'] = f'Activé ({hsts_value})'
            else:
                details['hsts'] = 'Désactivé'
                # Recommandation gérée par Security Headers pour éviter la duplication
        except:
            details['hsts'] = 'Non vérifiable'
        
        # Détermination status & severity (ALIGNÉ DNS)
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
            module_name="SSL/TLS Security",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations
        )
    
    except Exception as e:
        return ModuleResult(
            module_name="SSL/TLS Security",
            status="error",
            severity=SeverityLevel.CRITICAL,
            score=0,
            details={"error": str(e)},
            recommendations=["Vérifier que le site utilise HTTPS"]
        )
