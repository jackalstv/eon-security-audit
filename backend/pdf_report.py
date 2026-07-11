from datetime import datetime
from pathlib import Path

MONTHS_FR = [
    'janvier', 'février', 'mars', 'avril', 'mai', 'juin',
    'juillet', 'août', 'septembre', 'octobre', 'novembre', 'décembre',
]

def _fmt_date_fr(dt: datetime) -> str:
    return f"{dt.day} {MONTHS_FR[dt.month - 1]} {dt.year}"

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

from api.models import ScanResult

TEMPLATES_DIR = Path(__file__).parent / 'templates'

# ── Helpers ───────────────────────────────────────────────────────────────────


def _score_color(score: int) -> str:
    if score < 40: return '#DC2626'
    if score < 60: return '#EA580C'
    if score < 75: return '#D97706'
    if score < 85: return '#2563EB'
    return '#16A34A'

def _score_label(score: int) -> str:
    if score < 40: return 'CRITIQUE'
    if score < 60: return 'ÉLEVÉ'
    if score < 75: return 'MOYEN'
    if score < 85: return 'BON'
    return 'EXCELLENT'

def _sev_color(sev: str) -> str:
    return {'critical': '#DC2626', 'high': '#EA580C', 'medium': '#D97706',
            'low': '#2563EB', 'info': '#6B7280'}.get(sev, '#6B7280')

def _sev_label(sev: str) -> str:
    return {'critical': 'CRITIQUE', 'high': 'ÉLEVÉ', 'medium': 'MOYEN',
            'low': 'FAIBLE', 'info': 'INFO'}.get(sev, sev.upper())

def _sev_order(sev: str) -> int:
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(sev, 5)

def _fmt_value(v) -> str:
    if isinstance(v, list):
        return ', '.join(str(x) for x in v) if v else '—'
    if isinstance(v, dict):
        parts = [f"{k}: {val}" for k, val in list(v.items())[:6]]
        return ' · '.join(parts) or '—'
    if isinstance(v, bool):
        return 'Oui' if v else 'Non'
    return str(v) if v is not None else '—'

# ── Jinja2 env ────────────────────────────────────────────────────────────────

def _build_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
    )
    env.filters['score_color'] = _score_color
    env.filters['score_label'] = _score_label
    env.filters['sev_color']   = _sev_color
    env.filters['sev_label']   = _sev_label
    env.filters['fmt_value']   = _fmt_value
    return env

# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf(result: ScanResult) -> bytes:
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for m in result.modules:
        sev = m.severity.value
        if sev in counts:
            counts[sev] += 1

    all_recs = sorted(
        [(m.severity.value, m.module_name, rec)
         for m in result.modules
         for rec in m.recommendations],
        key=lambda x: _sev_order(x[0]),
    )

    sorted_modules = sorted(result.modules, key=lambda m: _sev_order(m.severity.value))

    env = _build_env()
    template = env.get_template('report.html.j2')
    html_str = template.render(
        result=result,
        sorted_modules=sorted_modules,
        counts=counts,
        all_recs=all_recs,
        score_color=_score_color(result.overall_score),
        score_label=_score_label(result.overall_score),
        cover_date=_fmt_date_fr(result.timestamp),
        generated_at=datetime.now().strftime('%d/%m/%Y à %H:%M'),
    )

    return HTML(
        string=html_str,
        base_url=str(TEMPLATES_DIR),
    ).write_pdf()
