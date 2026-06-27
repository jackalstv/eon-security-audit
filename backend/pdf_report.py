from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.graphics.shapes import Drawing, Rect, String as RLS, Circle, Line
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from api.models import ScanResult

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm
CW = PAGE_W - 2 * MARGIN

# Neutral palette — colors only for severity text/accents, never for backgrounds
C_INK     = colors.HexColor('#111827')   # titles, strong text
C_BODY    = colors.HexColor('#374151')   # body text
C_MUTED   = colors.HexColor('#6B7280')   # labels, captions
C_LIGHT   = colors.HexColor('#F3F4F6')   # card backgrounds, table stripes
C_BORDER  = colors.HexColor('#E5E7EB')   # borders, separators
C_WHITE   = colors.white

# Severity — text/accent only
C_CRITICAL = colors.HexColor('#DC2626')
C_HIGH     = colors.HexColor('#EA580C')
C_MEDIUM   = colors.HexColor('#D97706')
C_LOW      = colors.HexColor('#2563EB')
C_GOOD     = colors.HexColor('#16A34A')

HX = {
    'critical': '#DC2626', 'high': '#EA580C', 'medium': '#D97706',
    'low': '#2563EB', 'good': '#16A34A', 'grey': '#6B7280',
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _score_color(score: int) -> colors.Color:
    if score < 40: return C_CRITICAL
    if score < 60: return C_HIGH
    if score < 75: return C_MEDIUM
    if score < 85: return C_LOW
    return C_GOOD

def _score_hex(score: int) -> str:
    if score < 40: return HX['critical']
    if score < 60: return HX['high']
    if score < 75: return HX['medium']
    if score < 85: return HX['low']
    return HX['good']

def _score_label(score: int) -> str:
    if score < 40: return 'CRITIQUE'
    if score < 60: return 'ÉLEVÉ'
    if score < 75: return 'MOYEN'
    if score < 85: return 'BON'
    return 'EXCELLENT'

def _sev_color(sev: str) -> colors.Color:
    return {'critical': C_CRITICAL, 'high': C_HIGH, 'medium': C_MEDIUM,
            'low': C_LOW, 'info': C_MUTED}.get(sev, C_MUTED)

def _sev_hex(sev: str) -> str:
    return {'critical': HX['critical'], 'high': HX['high'], 'medium': HX['medium'],
            'low': HX['low'], 'info': HX['grey']}.get(sev, HX['grey'])

def _sev_label(sev: str) -> str:
    return {'critical': 'CRITIQUE', 'high': 'ÉLEVÉ', 'medium': 'MOYEN',
            'low': 'FAIBLE', 'info': 'INFO'}.get(sev, sev.upper())

def _sev_order(sev: str) -> int:
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(sev, 5)

def _status_label(status: str) -> str:
    return {'success': 'OK', 'warning': 'Attention', 'error': 'Erreur',
            'info': 'Info'}.get(status, status)

def _fmt_value(v) -> str:
    if isinstance(v, list):
        return ', '.join(str(x) for x in v) if v else '—'
    if isinstance(v, dict):
        parts = [f"{dk}: {dv}" for dk, dv in list(v.items())[:6]]
        return ' | '.join(parts) or '—'
    if isinstance(v, bool):
        return 'Oui' if v else 'Non'
    return str(v) if v is not None else '—'


# ── Drawings ──────────────────────────────────────────────────────────────────

def _draw_score_ring(score: int, size: float = 120) -> Drawing:
    """Thin colored ring with score number — clean, minimal."""
    d = Drawing(size, size)
    cx = cy = size / 2
    col = _score_color(score)
    r = size * 0.44
    ring_w = r * 0.18  # thin ring

    # Faint gray track
    track = Circle(cx, cy, r - ring_w / 2)
    track.fillColor = None
    track.strokeColor = C_BORDER
    track.strokeWidth = ring_w
    d.add(track)

    # Colored ring on top
    ring = Circle(cx, cy, r - ring_w / 2)
    ring.fillColor = None
    ring.strokeColor = col
    ring.strokeWidth = ring_w
    d.add(ring)

    # White inner fill
    inner = Circle(cx, cy, r - ring_w - 1)
    inner.fillColor = C_WHITE
    inner.strokeColor = None
    d.add(inner)

    # Score number
    d.add(RLS(cx, cy - size * 0.07, str(score),
              textAnchor='middle', fontSize=size * 0.22,
              fontName='Helvetica-Bold', fillColor=C_INK))
    d.add(RLS(cx, cy - size * 0.23, '/100',
              textAnchor='middle', fontSize=size * 0.10,
              fontName='Helvetica', fillColor=C_MUTED))
    return d


def _draw_stat_boxes(counts: dict) -> Drawing:
    """Severity counts — light card, colored number, neutral label."""
    items = [
        (str(counts['critical']), 'CRITIQUE', C_CRITICAL),
        (str(counts['high']),     'ÉLEVÉ',    C_HIGH),
        (str(counts['medium']),   'MOYEN',    C_MEDIUM),
        (str(counts['low']),      'FAIBLE',   C_LOW),
    ]
    bh = 1.9 * cm
    gap = 0.3 * cm
    bw = (CW - 3 * gap) / 4
    d = Drawing(CW, bh + 0.2 * cm)

    for idx, (val, lbl, col) in enumerate(items):
        x = idx * (bw + gap)

        # Light card background
        bg = Rect(x, 0.1 * cm, bw, bh)
        bg.fillColor = C_LIGHT
        bg.strokeColor = C_BORDER
        bg.strokeWidth = 0.5
        bg.rx = bg.ry = 3
        d.add(bg)

        # Thin colored top border
        top = Rect(x, bh - 0.01 * cm + 0.1 * cm, bw, 0.15 * cm)
        top.fillColor = col
        top.strokeColor = None
        top.rx = top.ry = 3
        d.add(top)

        # Count number (colored)
        d.add(RLS(x + bw / 2, bh - 0.45 * cm, val,
                  textAnchor='middle', fontSize=22,
                  fontName='Helvetica-Bold', fillColor=col))

        # Label (neutral gray)
        d.add(RLS(x + bw / 2, 0.28 * cm, lbl,
                  textAnchor='middle', fontSize=7,
                  fontName='Helvetica-Bold', fillColor=C_MUTED))

    return d


def _draw_bars(modules) -> Drawing:
    row_h = 26
    label_w = 150
    score_w = 55
    bar_w = CW * 0.88 - label_w - score_w
    width = label_w + bar_w + score_w
    height = len(modules) * row_h + 8
    d = Drawing(width, height)

    for i, m in enumerate(modules):
        y = height - (i + 1) * row_h + 4
        col = _score_color(m.score)

        sep = Rect(0, y - 1, width, 0.5)
        sep.fillColor = C_BORDER
        sep.strokeColor = None
        d.add(sep)

        d.add(RLS(0, y + 8, m.module_name[:28],
                  fontSize=9, fontName='Helvetica', fillColor=C_BODY))

        # Track
        track_bg = Rect(label_w, y + 5, bar_w, row_h - 13)
        track_bg.fillColor = C_LIGHT
        track_bg.strokeColor = None
        d.add(track_bg)

        # Progress bar
        fw = max(3.0, bar_w * m.score / 100)
        bar = Rect(label_w, y + 5, fw, row_h - 13)
        bar.fillColor = col
        bar.strokeColor = None
        d.add(bar)

        d.add(RLS(label_w + bar_w + 6, y + 8, f'{m.score}/100',
                  fontSize=9, fontName='Helvetica-Bold', fillColor=col))

    return d


def _draw_page_header(domain: str) -> Drawing:
    """Minimal top-of-page header: ÉON left, domain right, dark rule below."""
    h = 1.2 * cm
    d = Drawing(CW, h)

    d.add(RLS(0, 0.38 * cm, 'ÉON',
              fontSize=14, fontName='Helvetica-Bold', fillColor=C_INK))
    d.add(RLS(CW, 0.38 * cm, f'Audit — {domain}',
              textAnchor='end', fontSize=8,
              fontName='Helvetica', fillColor=C_MUTED))

    # Dark rule
    rule = Rect(0, 0, CW, 1.2)
    rule.fillColor = C_INK
    rule.strokeColor = None
    d.add(rule)

    return d


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles() -> dict:
    b = getSampleStyleSheet()

    def p(name, **kw):
        return ParagraphStyle(name, parent=b['Normal'], **kw)

    return {
        'h2':           p('h2',  fontName='Helvetica-Bold', fontSize=12,
                           textColor=C_INK, spaceBefore=14, spaceAfter=4),
        'body':         p('body', fontName='Helvetica', fontSize=10,
                           textColor=C_BODY, leading=14, spaceAfter=4),
        'small':        p('small', fontName='Helvetica', fontSize=8,
                           textColor=C_MUTED, leading=11, spaceAfter=2),
        'th':           p('th', fontName='Helvetica-Bold', fontSize=9,
                           textColor=C_WHITE, leading=12),
        'th_c':         p('th_c', fontName='Helvetica-Bold', fontSize=9,
                           textColor=C_WHITE, leading=12, alignment=TA_CENTER),
        'td':           p('td', fontName='Helvetica', fontSize=9,
                           textColor=C_BODY, leading=12),
        'td_c':         p('td_c', fontName='Helvetica', fontSize=9,
                           textColor=C_BODY, leading=12, alignment=TA_CENTER),
        'td_key':       p('td_key', fontName='Helvetica-Bold', fontSize=8,
                           textColor=C_MUTED, leading=11),
        'td_val':       p('td_val', fontName='Helvetica', fontSize=8,
                           textColor=C_BODY, leading=12),
        'td_rec':       p('td_rec', fontName='Helvetica', fontSize=8,
                           textColor=C_BODY, leading=12),
        'rec':          p('rec', fontName='Helvetica', fontSize=9,
                           textColor=C_BODY, leading=13, spaceAfter=4, leftIndent=10),
        'cover_sub':    p('cover_sub', fontName='Helvetica', fontSize=11,
                           textColor=C_MUTED, alignment=TA_CENTER, spaceAfter=4),
        'cover_domain': p('cover_domain', fontName='Helvetica-Bold', fontSize=24,
                           textColor=C_INK, alignment=TA_CENTER, spaceAfter=2),
        'center_sm':    p('center_sm', fontName='Helvetica', fontSize=8,
                           textColor=C_MUTED, alignment=TA_CENTER),
        'center_sm_r':  p('center_sm_r', fontName='Helvetica', fontSize=8,
                           textColor=C_MUTED, alignment=TA_RIGHT),
    }


# ── Table style ───────────────────────────────────────────────────────────────

def _base_table_style(header: bool = True) -> list:
    s = [
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('GRID',          (0, 0), (-1, -1), 0.5, C_BORDER),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_WHITE, C_LIGHT]),
    ]
    if header:
        s += [('BACKGROUND', (0, 0), (-1, 0), C_INK)]
    return s


# ── Footer ────────────────────────────────────────────────────────────────────

def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(C_MUTED)
    canvas.drawCentredString(
        PAGE_W / 2, 0.7 * cm,
        f"ÉON — Rapport d'Audit de Sécurité  ·  Page {canvas.getPageNumber()}",
    )
    canvas.restoreState()


# ── Pages ─────────────────────────────────────────────────────────────────────

def _cover(result: ScanResult, S: dict) -> list:
    e = []
    col = _score_color(result.overall_score)

    e.append(_draw_page_header(result.domain))
    e.append(Spacer(1, 2.2 * cm))

    e.append(Paragraph("Rapport d'Audit de Sécurité", S['cover_sub']))
    e.append(Spacer(1, 0.3 * cm))
    e.append(Paragraph(result.domain, S['cover_domain']))
    e.append(Paragraph(
        f"Plateforme : <b>{result.platform.value.capitalize()}</b>",
        S['center_sm'],
    ))
    e.append(Spacer(1, 1.6 * cm))

    # Score ring centered
    sz = 140
    ct = Table([[_draw_score_ring(result.overall_score, sz)]], colWidths=[CW])
    ct.setStyle(TableStyle([('ALIGN', (0, 0), (0, 0), 'CENTER')]))
    e.append(ct)
    e.append(Spacer(1, 0.3 * cm))

    label_d = Drawing(CW, 0.8 * cm)
    label_d.add(RLS(CW / 2, 0.12 * cm,
                    f"Niveau de risque global : {_score_label(result.overall_score)}",
                    textAnchor='middle', fontSize=12,
                    fontName='Helvetica-Bold', fillColor=col))
    e.append(label_d)
    e.append(Spacer(1, 1.8 * cm))

    # Metadata table
    meta = [
        ['Date du scan',     result.timestamp.strftime('%d/%m/%Y à %H:%M')],
        ['Référence',        result.scan_id[:28] + '…'],
        ['Modules analysés', str(len(result.modules))],
        ['Score global',     f"{result.overall_score}/100 — {_score_label(result.overall_score)}"],
    ]
    mt = Table(meta, colWidths=[3.8 * cm, 9 * cm], hAlign='CENTER')
    mt.setStyle(TableStyle([
        ('FONTNAME',      (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME',      (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE',      (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',     (0, 0), (0, -1), C_MUTED),
        ('TEXTCOLOR',     (1, 0), (1, -1), C_BODY),
        ('ROWBACKGROUNDS',(0, 0), (-1, -1), [C_LIGHT, C_WHITE]),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
        ('GRID',          (0, 0), (-1, -1), 0.5, C_BORDER),
    ]))
    e.append(Table([[mt]], colWidths=[CW]))
    e.append(Spacer(1, 2.5 * cm))

    e.append(HRFlowable(width='100%', thickness=0.5, color=C_BORDER))
    e.append(Spacer(1, 0.3 * cm))
    e.append(Paragraph(
        'Projet M1 Cybersécurité — ESGI 2025-2026  ·  Document Confidentiel',
        S['center_sm'],
    ))
    e.append(PageBreak())
    return e


def _summary(result: ScanResult, S: dict) -> list:
    e = []

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for m in result.modules:
        sev = m.severity.value
        if sev in counts:
            counts[sev] += 1

    e.append(Paragraph('Résumé Exécutif', S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=10))
    e.append(_draw_stat_boxes(counts))
    e.append(Spacer(1, 0.5 * cm))

    for threshold, text in [
        (40,  'La posture de sécurité est <b>critique</b>. Des actions immédiates sont requises.'),
        (60,  'La posture de sécurité présente des <b>risques élevés</b>. Des mesures correctives urgentes sont recommandées.'),
        (75,  'La posture de sécurité est <b>moyenne</b>. Plusieurs améliorations sont à apporter.'),
        (85,  'La posture de sécurité est <b>bonne</b>. Quelques ajustements permettraient d\'atteindre l\'excellence.'),
        (101, 'La posture de sécurité est <b>excellente</b>. Continuez à maintenir ces bonnes pratiques.'),
    ]:
        if result.overall_score < threshold:
            e.append(Paragraph(text, S['body']))
            break

    e.append(Spacer(1, 0.5 * cm))
    e.append(Paragraph("Vue d'ensemble des modules", S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=8))

    w1, w2, w3, w4 = CW * 0.40, CW * 0.14, CW * 0.21, CW * 0.25
    rows = [[
        Paragraph('Module',   S['th']),
        Paragraph('Score',    S['th_c']),
        Paragraph('Sévérité', S['th_c']),
        Paragraph('Statut',   S['th_c']),
    ]]
    for m in result.modules:
        rows.append([
            Paragraph(m.module_name, S['td']),
            Paragraph(f'<font color="{_score_hex(m.score)}"><b>{m.score}/100</b></font>', S['td_c']),
            Paragraph(f'<font color="{_sev_hex(m.severity.value)}"><b>{_sev_label(m.severity.value)}</b></font>', S['td_c']),
            Paragraph(_status_label(m.status), S['td_c']),
        ])

    tbl = Table(rows, colWidths=[w1, w2, w3, w4])
    tbl.setStyle(TableStyle(_base_table_style()))
    e.append(tbl)
    e.append(Spacer(1, 0.5 * cm))

    e.append(Paragraph('Scores par module', S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=10))
    bt = Table([[_draw_bars(result.modules)]], colWidths=[CW])
    bt.setStyle(TableStyle([
        ('ALIGN',         (0, 0), (0, 0), 'CENTER'),
        ('TOPPADDING',    (0, 0), (0, 0), 8),
        ('BOTTOMPADDING', (0, 0), (0, 0), 8),
    ]))
    e.append(bt)
    e.append(PageBreak())
    return e


def _module_details(result: ScanResult, S: dict) -> list:
    e = []
    e.append(Paragraph('Analyse Détaillée par Module', S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=4))

    w_key = 4.5 * cm
    w_val = CW - w_key

    for m in result.modules:
        col = _score_color(m.score)
        sev_col = _sev_color(m.severity.value)
        block = []

        # Module header band — light background, colored left accent bar
        hd = Drawing(CW, 1.2 * cm)
        hd_bg = Rect(0, 0, CW, 1.2 * cm)
        hd_bg.fillColor = C_LIGHT
        hd_bg.strokeColor = None
        hd.add(hd_bg)
        accent = Rect(0, 0, 0.3 * cm, 1.2 * cm)
        accent.fillColor = col
        accent.strokeColor = None
        hd.add(accent)
        hd.add(RLS(0.55 * cm, 0.36 * cm, m.module_name,
                   fontSize=11, fontName='Helvetica-Bold', fillColor=C_INK))
        hd.add(RLS(CW - 0.3 * cm, 0.6 * cm, f'{m.score}/100',
                   textAnchor='end', fontSize=13,
                   fontName='Helvetica-Bold', fillColor=col))
        hd.add(RLS(CW - 0.3 * cm, 0.16 * cm, _sev_label(m.severity.value),
                   textAnchor='end', fontSize=8,
                   fontName='Helvetica-Bold', fillColor=sev_col))
        block.append(hd)

        if m.details:
            rows = []
            for k, v in m.details.items():
                rows.append([
                    Paragraph(k.replace('_', ' ').capitalize(), S['td_key']),
                    Paragraph(_fmt_value(v), S['td_val']),
                ])
            if rows:
                dt = Table(rows, colWidths=[w_key, w_val], hAlign='LEFT')
                dt.setStyle(TableStyle([
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_WHITE, C_LIGHT]),
                    ('TOPPADDING',     (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING',  (0, 0), (-1, -1), 6),
                    ('LEFTPADDING',    (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING',   (0, 0), (-1, -1), 8),
                    ('VALIGN',         (0, 0), (-1, -1), 'TOP'),
                    ('GRID',           (0, 0), (-1, -1), 0.5, C_BORDER),
                ]))
                block.append(Spacer(1, 0.2 * cm))
                block.append(dt)

        if m.recommendations:
            block.append(Spacer(1, 0.25 * cm))
            block.append(Paragraph('Recommandations :', S['small']))
            for rec in m.recommendations:
                block.append(Paragraph(f'→  {rec}', S['rec']))

        block.append(Spacer(1, 0.5 * cm))
        e.append(KeepTogether(block))

    e.append(PageBreak())
    return e


def _action_plan(result: ScanResult, S: dict) -> list:
    e = []
    e.append(Paragraph("Plan d'Action", S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_BORDER, spaceAfter=6))
    e.append(Paragraph(
        'Recommandations classées par priorité décroissante. '
        'Traitez en priorité les niveaux CRITIQUE et ÉLEVÉ.',
        S['body'],
    ))
    e.append(Spacer(1, 0.4 * cm))

    all_recs = sorted(
        [(m.severity.value, m.module_name, rec)
         for m in result.modules
         for rec in m.recommendations],
        key=lambda x: _sev_order(x[0]),
    )

    if not all_recs:
        e.append(Paragraph('Aucune recommandation — excellent résultat.', S['body']))
    else:
        w_p = CW * 0.15
        w_m = CW * 0.26
        w_r = CW * 0.59

        rows = [[
            Paragraph('Priorité',       S['th_c']),
            Paragraph('Module',         S['th']),
            Paragraph('Recommandation', S['th']),
        ]]
        for sev, module, rec in all_recs:
            rows.append([
                Paragraph(f'<font color="{_sev_hex(sev)}"><b>{_sev_label(sev)}</b></font>', S['td_c']),
                Paragraph(module, S['td']),
                Paragraph(rec, S['td_rec']),
            ])

        tbl = Table(rows, colWidths=[w_p, w_m, w_r], repeatRows=1)
        tbl.setStyle(TableStyle(_base_table_style()))
        e.append(tbl)

    e.append(Spacer(1, 1 * cm))
    e.append(HRFlowable(width='100%', thickness=0.5, color=C_BORDER))
    e.append(Spacer(1, 0.3 * cm))
    e.append(Paragraph(
        f"Rapport généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} "
        f"— ÉON Audit de Sécurité · ESGI 2025-2026",
        S['center_sm'],
    ))
    return e


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf(result: ScanResult) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=1.5 * cm,
        title=f"Rapport de Sécurité — {result.domain}",
        author='ÉON Security Audit',
    )
    S = _styles()
    elements = (
        _cover(result, S)
        + _summary(result, S)
        + _module_details(result, S)
        + _action_plan(result, S)
    )
    doc.build(elements, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
