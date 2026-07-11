
import dns.resolver
import smtplib
import socket
from api.models import ModuleResult, SeverityLevel


def analyze_email(domain: str) -> ModuleResult:
    """Analyse la sécurité de la configuration email (MX, anti-spam, STARTTLS)"""
    try:
        score = 0
        details = {}
        recommendations = []

        # 1. Vérifier les enregistrements MX (25 points)
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_hosts = [str(mx.exchange).rstrip('.') for mx in mx_records]
            score += 25
            details["mx_records"] = f"{len(mx_hosts)} serveur(s) trouvé(s)"
            details["mx_hosts"] = mx_hosts
        except Exception:
            mx_hosts = []
            details["mx_records"] = "aucun enregistrement MX"
            recommendations.append(
                "Configurer des enregistrements MX pour recevoir des emails"
            )

        # 2. Redondance MX - plusieurs serveurs (20 points)
        if len(mx_hosts) >= 2:
            score += 20
            details["mx_redundancy"] = "oui"
        elif len(mx_hosts) == 1:
            details["mx_redundancy"] = "non (1 seul serveur)"
            recommendations.append(
                "Ajouter un serveur MX secondaire pour assurer la redondance"
            )
        else:
            details["mx_redundancy"] = "non applicable"

        # 3. Support STARTTLS sur le serveur mail principal (30 points)
        if mx_hosts:
            try:
                smtp = smtplib.SMTP(mx_hosts[0], 25, timeout=10)
                smtp.ehlo()
                if smtp.has_extn('STARTTLS'):
                    score += 30
                    details["starttls"] = "supporté"
                else:
                    details["starttls"] = "non supporté"
                    recommendations.append(
                        "Activer STARTTLS sur le serveur mail pour chiffrer les échanges"
                    )
                smtp.quit()
            except Exception:
                score += 30  # bénéfice du doute : port 25 souvent filtré sur Exchange/Google
                details["starttls"] = "non vérifiable"
        else:
            details["starttls"] = "non applicable"

        # 4. Banner SMTP non verbose (25 points)
        if mx_hosts:
            try:
                sock = socket.create_connection((mx_hosts[0], 25), timeout=10)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                sock.close()

                details["smtp_banner"] = banner
                # Vérifier si le banner expose trop d'infos (version, OS, etc.)
                keywords_verbose = ["version", "ubuntu", "debian", "centos", "postfix"]
                is_verbose = any(kw in banner.lower() for kw in keywords_verbose)

                if not is_verbose:
                    score += 25
                    details["banner_exposure"] = "discret"
                else:
                    details["banner_exposure"] = "trop d'informations exposées"
                    recommendations.append(
                        "Réduire les informations dans le banner SMTP pour limiter la reconnaissance"
                    )
            except Exception:
                details["smtp_banner"] = "non récupérable"
                details["banner_exposure"] = "non vérifiable"
        else:
            details["smtp_banner"] = "non applicable"

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
            module_name="Email Security",
            status=status,
            severity=severity,
            score=score,
            details=details,
            recommendations=recommendations
        )

    except Exception as e:
        return ModuleResult(
            module_name="Email Security",
            status="error",
            severity=SeverityLevel.HIGH,
            score=0,
            details={"error": str(e)},
            recommendations=[
                "Impossible d'analyser la configuration email du domaine"
            ]
        )
