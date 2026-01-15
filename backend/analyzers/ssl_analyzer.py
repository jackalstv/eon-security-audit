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
                    recommendations.append(f"Mettre à jour vers TLS 1.2+ (actuellement {tls_version})")
        
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
            recommendations.append(f"Renouveler le certificat SSL (expire dans {days_remaining} jours)")
        else:
            details['certificate'] = 'EXPIRÉ'
            recommendations.append("URGENT : Renouveler le certificat SSL immédiatement")
        
        # 3. Vérifier HSTS
        try:
            response = requests.get(f"https://{domain}", timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if 'Strict-Transport-Security' in response.headers:
                score += 30
                hsts_value = response.headers['Strict-Transport-Security']
                details['hsts'] = f'Activé ({hsts_value})'
            else:
                details['hsts'] = 'Désactivé'
                recommendations.append("Activer HSTS pour forcer HTTPS")
        except:
            details['hsts'] = 'Non vérifiable'
        
        return ModuleResult(
            module_name="SSL/TLS Security",
            status="success",
            severity=SeverityLevel.LOW,
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
