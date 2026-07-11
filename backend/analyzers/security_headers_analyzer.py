
import requests
from api.models import ModuleResult, SeverityLevel


def analyze_security_headers(domain: str) -> ModuleResult:
    """Analyse les en-têtes HTTP de sécurité (OWASP / ANSSI)"""
    try:
        score = 0
        details = {}
        recommendations = []

        # Requête HTTP(S)
        try:
            response = requests.get(
                f"https://{domain}",
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True
            )
            headers = response.headers
        except Exception:
            response = requests.get(
                f"http://{domain}",
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=True
            )
            headers = response.headers

        # 1. Content-Security-Policy (25 points)
        if "Content-Security-Policy" in headers:
            score += 25
            details["csp"] = "présente"
        else:
            details["csp"] = "absente"
            recommendations.append(
                "Votre site n'est pas protégé contre l'injection de code malveillant (attaques XSS). "
                "Un pirate pourrait afficher du faux contenu à vos visiteurs ou voler leurs données. "
                "Demandez à votre développeur ou hébergeur d'activer la Content Security Policy."
            )

        # 2. X-Frame-Options (20 points)
        if "X-Frame-Options" in headers:
            score += 20
            details["x_frame_options"] = headers.get("X-Frame-Options")
        else:
            details["x_frame_options"] = "absent"
            recommendations.append(
                "Votre site peut être intégré dans une autre page web à votre insu, "
                "permettant de tromper vos visiteurs en leur faisant croire qu'ils interagissent avec votre site. "
                "Demandez à votre hébergeur d'activer la protection contre le détournement de clics (X-Frame-Options)."
            )

        # 3. X-Content-Type-Options (15 points)
        if headers.get("X-Content-Type-Options") == "nosniff":
            score += 15
            details["x_content_type_options"] = "nosniff"
        else:
            details["x_content_type_options"] = "absent ou incorrect"
            recommendations.append(
                "Votre site laisse les navigateurs interpréter librement le type des fichiers téléchargés, "
                "ce qui peut permettre l'exécution de fichiers malveillants. "
                "Demandez à votre hébergeur d'activer l'option X-Content-Type-Options."
            )

        # 4. Strict-Transport-Security (25 points)
        if "Strict-Transport-Security" in headers:
            score += 25
            details["hsts"] = headers.get("Strict-Transport-Security")
        else:
            details["hsts"] = "absent"
            recommendations.append(
                "Votre site n'impose pas les connexions sécurisées (HTTPS). "
                "Des visiteurs pourraient accéder à votre site en mode non chiffré et voir leurs données interceptées. "
                "Demandez à votre hébergeur d'activer HSTS."
            )

        # 5. Referrer-Policy (15 points)
        if "Referrer-Policy" in headers:
            score += 15
            details["referrer_policy"] = headers.get("Referrer-Policy")
        else:
            details["referrer_policy"] = "absente"
            recommendations.append(
                "Votre site transmet des informations sur la navigation de vos visiteurs à des sites tiers "
                "(pages visitées, URLs internes). Demandez à votre hébergeur de configurer la Referrer Policy "
                "pour limiter ces fuites."
            )

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
            module_name="Security Headers",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations
        )

    except Exception as e:
        return ModuleResult(
            module_name="Security Headers",
            status="error",
            severity=SeverityLevel.HIGH,
            score=0,
            details={"error": str(e)},
            recommendations=[
                "Impossible d'analyser les en-têtes HTTP du domaine"
            ]
        )
