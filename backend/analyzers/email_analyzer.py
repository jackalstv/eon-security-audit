
import dns.resolver
import smtplib
import socket
from api.models import ModuleResult, SeverityLevel


def analyze_email(domain: str) -> ModuleResult:
    #Analyse la sécurité de la configuration email (MX, anti-spam, STARTTLS)
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
                "Votre domaine n'est pas configuré pour recevoir des emails. "
                "Tous les messages envoyés à une adresse @votredomaine seront rejetés ou perdus. "
                "Contactez votre hébergeur pour configurer la messagerie."
            )

        # 2. Redondance MX - plusieurs serveurs (20 points)
        mx_primary = mx_hosts[0].lower() if mx_hosts else ''
        is_m365 = 'protection.outlook.com' in mx_primary
        is_google = 'aspmx.l.google.com' in mx_primary or 'googlemail.com' in mx_primary

        if len(mx_hosts) >= 2:
            score += 20
            details["mx_redundancy"] = "oui"
        elif len(mx_hosts) == 1:
            if is_m365:
                score += 20
                details["mx_redundancy"] = "géré par Microsoft 365 (redondance interne)"
            elif is_google:
                score += 20
                details["mx_redundancy"] = "géré par Google Workspace (redondance interne)"
            else:
                details["mx_redundancy"] = "non (1 seul serveur)"
                recommendations.append(
                    "Votre messagerie ne repose que sur un seul serveur. En cas de panne, "
                    "vous ne pourrez plus recevoir d'emails pendant toute la durée de l'incident. "
                    "Demandez à votre hébergeur de configurer un serveur de messagerie de secours."
                )
        else:
            details["mx_redundancy"] = "non applicable"

        # 3+4. Vérifier STARTTLS et bannière SMTP
        smtp_unreachable = False
        if mx_hosts:
            # Providers cloud connus : STARTTLS garanti, bannière non exposée
            if is_m365:
                score += 30 + 25
                details["starttls"] = "supporté (Microsoft 365)"
                details["smtp_banner"] = "géré par Microsoft 365"
                details["banner_exposure"] = "discret (géré par Microsoft)"
            elif is_google:
                score += 30 + 25
                details["starttls"] = "supporté (Google Workspace)"
                details["smtp_banner"] = "géré par Google Workspace"
                details["banner_exposure"] = "discret (géré par Google)"
            else:
                # Tenter une connexion SMTP sur port 25, puis 587 en fallback
                smtp_connected = False
                for port in [25, 587]:
                    try:
                        smtp = smtplib.SMTP(mx_hosts[0], port, timeout=10)
                        # La bannière est dans la réponse initiale du serveur
                        banner = smtp.getwelcome()
                        if isinstance(banner, bytes):
                            banner = banner.decode('utf-8', errors='ignore')
                        banner = str(banner).strip()
                        smtp.ehlo()

                        # Vérifier STARTTLS (30 points)
                        if smtp.has_extn('STARTTLS'):
                            score += 30
                            details["starttls"] = f"supporté (port {port})"
                        else:
                            details["starttls"] = "non supporté"
                            recommendations.append(
                                "Les emails reçus sur votre serveur ne sont pas chiffrés pendant leur transit. "
                                "Le contenu de vos emails professionnels pourrait être intercepté par un tiers. "
                                "Contactez votre prestataire de messagerie pour activer le chiffrement STARTTLS."
                            )

                        # Vérifier bannière (25 points)
                        details["smtp_banner"] = banner
                        keywords_verbose = ["version", "ubuntu", "debian", "centos", "postfix"]
                        is_verbose = any(kw in banner.lower() for kw in keywords_verbose)
                        if not is_verbose:
                            score += 25
                            details["banner_exposure"] = "discret"
                        else:
                            details["banner_exposure"] = "trop d'informations exposées"
                            recommendations.append(
                                "Votre serveur de messagerie révèle des informations techniques à quiconque le contacte "
                                "(version du logiciel, système d'exploitation). Ces informations aident les pirates à "
                                "cibler des failles connues. Demandez à votre administrateur système de masquer ces données."
                            )

                        smtp.quit()
                        smtp_connected = True
                        break
                    except Exception:
                        continue

                if not smtp_connected:
                    smtp_unreachable = True
                    details["starttls"] = "non évalué (ports 25 et 587 inaccessibles depuis le scanner)"
                    details["smtp_banner"] = "non évalué"
                    details["banner_exposure"] = "non évalué"
                    recommendations.append(
                        "La vérification du chiffrement STARTTLS et de la bannière SMTP n'a pas pu être effectuée "
                        "depuis notre scanner (ports 25 et 587 filtrés par votre hébergeur ou pare-feu) : "
                        "ces critères sont exclus du calcul du score. "
                        "Si vous gérez votre propre serveur mail, vérifiez que STARTTLS est bien activé "
                        "et que la bannière SMTP ne révèle pas la version du logiciel."
                    )
        else:
            details["starttls"] = "non applicable"
            details["smtp_banner"] = "non applicable"

        # Ports SMTP filtrés : impossible de vérifier STARTTLS et la bannière (55 pts),
        # on note sur les 45 points vérifiables et on remet sur 100
        if smtp_unreachable:
            details["bareme"] = "score calculé sur les vérifications réalisables uniquement"
            score = round(score * 100 / 45)

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
