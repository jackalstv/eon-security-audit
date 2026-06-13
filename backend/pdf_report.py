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
from reportlab.graphics.shapes import Drawing, Rect, String as RLS, Circle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from api.models import ScanResult

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm
CW = PAGE_W - 2 * MARGIN  # content width

# Palette
C_PURPLE  = colors.HexColor('#8B5CF6')
C_CRITICAL= colors.HexColor('#DC2626')
C_HIGH    = colors.HexColor('#EA580C')
C_MEDIUM  = colors.HexColor('#D97706')
C_LOW     = colors.HexColor('#2563EB')
C_GOOD    = colors.HexColor('#16A34A')
C_GREY    = colors.HexColor('#6B7280')
C_LGREY   = colors.HexColor('#F3F4F6')
C_DARK    = colors.HexColor('#111827')
C_SUBTLE  = colors.HexColor('#4B5563')
C_WHITE   = colors.white


# ── Helpers ──────────────────────────────────────────────────────────────────

def _score_color(score: int) -> colors.Color:
    if score < 40: return C_CRITICAL
    if score < 60: return C_HIGH
    if score < 75: return C_MEDIUM
    if score < 85: return C_LOW
    return C_GOOD

def _score_label(score: int) -> str:
    if score < 40: return 'CRITIQUE'
    if score < 60: return 'ÉLEVÉ'
    if score < 75: return 'MOYEN'
    if score < 85: return 'BON'
    return 'EXCELLENT'

def _sev_color(sev: str) -> colors.Color:
    return {'critical': C_CRITICAL, 'high': C_HIGH, 'medium': C_MEDIUM,
            'low': C_LOW, 'info': C_GREY}.get(sev, C_GREY)

def _sev_label(sev: str) -> str:
    return {'critical': 'CRITIQUE', 'high': 'ÉLEVÉ', 'medium': 'MOYEN',
            'low': 'FAIBLE', 'info': 'INFO'}.get(sev, sev.upper())

def _sev_order(sev: str) -> int:
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(sev, 5)

def _status_label(status: str) -> str:
    return {'success': 'OK', 'warning': 'Attention', 'error': 'Erreur', 'info': 'Info'}.get(status, status)


# ── Drawings ─────────────────────────────────────────────────────────────────

def _draw_score_circle(score: int, size: float = 120) -> Drawing:
    d = Drawing(size, size)
    cx = cy = size / 2
    col = _score_color(score)

    outer = Circle(cx, cy, size * 0.46)
    outer.fillColor = col
    outer.strokeColor = None
    d.add(outer)

    inner = Circle(cx, cy, size * 0.31)
    inner.fillColor = C_WHITE
    inner.strokeColor = None
    d.add(inner)

    d.add(RLS(cx, cy - size * 0.09, str(score),
              textAnchor='middle', fontSize=size * 0.24,
              fontName='Helvetica-Bold', fillColor=col))
    d.add(RLS(cx, cy - size * 0.25, '/100',
              textAnchor='middle', fontSize=size * 0.11,
              fontName='Helvetica', fillColor=C_GREY))
    return d


def _draw_bars(modules, width: float = CW * 0.93) -> Drawing:
    row_h, label_w, score_w = 26, 160, 48
    bar_w = width - label_w - score_w
    height = len(modules) * row_h + 4
    d = Drawing(width, height)

    for i, m in enumerate(modules):
        y = height - (i + 1) * row_h + 2
        col = _score_color(m.score)

        d.add(RLS(0, y + 8, m.module_name,
                  fontSize=9, fontName='Helvetica', fillColor=C_DARK))

        bg = Rect(label_w, y + 3, bar_w, row_h - 10)
        bg.fillColor = C_LGREY
        bg.strokeColor = None
        d.add(bg)

        fw = max(2.0, bar_w * m.score / 100)
        bar = Rect(label_w, y + 3, fw, row_h - 10)
        bar.fillColor = col
        bar.strokeColor = None
        d.add(bar)

        d.add(RLS(label_w + bar_w + 6, y + 8, f"{m.score}/100",
                  fontSize=9, fontName='Helvetica-Bold', fillColor=col))
    return d


def _draw_header_band(text_left: str, text_right: str) -> Drawing:
    d = Drawing(CW, 2.2 * cm)
    bg = Rect(0, 0, CW, 2.2 * cm)
    bg.fillColor = C_PURPLE
    bg.strokeColor = None
    d.add(bg)
    d.add(RLS(14, 0.65 * cm, text_left,
              fontSize=26, fontName='Helvetica-Bold', fillColor=C_WHITE))
    d.add(RLS(CW - 14, 0.75 * cm, text_right,
              textAnchor='end', fontSize=10, fontName='Helvetica', fillColor=C_WHITE))
    return d


def _stat_boxes(counts: dict) -> Drawing:
    items = [
        (str(counts['critical']), 'CRITIQUE', C_CRITICAL),
        (str(counts['high']),    'ÉLEVÉ',    C_HIGH),
        (str(counts['medium']),  'MOYEN',    C_MEDIUM),
        (str(counts['low']),     'FAIBLE',   C_LOW),
    ]
    box_h = 2 * cm
    gap = 0.3 * cm
    bw = (CW - 3 * gap) / 4
    d = Drawing(CW, box_h + 0.2 * cm)

    for idx, (val, lbl, col) in enumerate(items):
        x = idx * (bw + gap)
        bg = Rect(x, 0.1 * cm, bw, box_h)
        bg.fillColor = col
        bg.strokeColor = None
        bg.rx = bg.ry = 4
        d.add(bg)
        d.add(RLS(x + bw / 2, box_h - 0.35 * cm, val,
                  textAnchor='middle', fontSize=22, fontName='Helvetica-Bold',
                  fillColor=C_WHITE))
        d.add(RLS(x + bw / 2, 0.3 * cm, lbl,
                  textAnchor='middle', fontSize=7, fontName='Helvetica-Bold',
                  fillColor=C_WHITE))
    return d


# ── Styles ───────────────────────────────────────────────────────────────────

def _styles() -> dict:
    b = getSampleStyleSheet()
    def p(name, **kw):
        return ParagraphStyle(name, parent=b['Normal'], **kw)
    return {
        'h2':          p('h2',  fontName='Helvetica-Bold', fontSize=14, textColor=C_PURPLE,
                          spaceBefore=14, spaceAfter=6),
        'h3':          p('h3',  fontName='Helvetica-Bold', fontSize=11, textColor=C_DARK,
                          spaceBefore=8, spaceAfter=4),
        'body':        p('body', fontName='Helvetica', fontSize=10, textColor=C_DARK,
                          leading=14, spaceAfter=4),
        'small':       p('small', fontName='Helvetica', fontSize=8, textColor=C_SUBTLE,
                          leading=11, spaceAfter=2),
        'rec':         p('rec',  fontName='Helvetica', fontSize=9, textColor=C_DARK,
                          leading=13, spaceAfter=4, leftIndent=10),
        'center':      p('center', fontName='Helvetica', fontSize=10, textColor=C_DARK,
                          alignment=TA_CENTER),
        'center_sm':   p('center_sm', fontName='Helvetica', fontSize=8, textColor=C_SUBTLE,
                          alignment=TA_CENTER),
        'cover_sub':   p('cover_sub', fontName='Helvetica', fontSize=13, textColor=C_SUBTLE,
                          alignment=TA_CENTER, spaceAfter=4),
        'cover_domain':p('cover_domain', fontName='Helvetica-Bold', fontSize=24,
                          textColor=C_PURPLE, alignment=TA_CENTER, spaceAfter=2),
    }


# ── Page builders ─────────────────────────────────────────────────────────────

def _cover(result: ScanResult, S: dict) -> list:
    e = []
    col = _score_color(result.overall_score)

    e.append(_draw_header_band('ÉON', 'Audit de Sécurité Automatisé'))
    e.append(Spacer(1, 1.8 * cm))

    e.append(Paragraph("RAPPORT D'AUDIT DE SÉCURITÉ", S['cover_sub']))
    e.append(Spacer(1, 0.4 * cm))
    e.append(Paragraph(result.domain, S['cover_domain']))
    e.append(Paragraph(f"Plateforme détectée : <b>{result.platform.value.capitalize()}</b>",
                       S['center_sm']))
    e.append(Spacer(1, 1.5 * cm))

    # Score circle
    sz = 150
    circle = _draw_score_circle(result.overall_score, sz)
    ct = Table([[circle]], colWidths=[CW])
    ct.setStyle(TableStyle([('ALIGN', (0, 0), (0, 0), 'CENTER')]))
    e.append(ct)
    e.append(Spacer(1, 0.2 * cm))

    label_d = Drawing(CW, 1 * cm)
    label_d.add(RLS(CW / 2, 0.15 * cm,
                    f"Niveau de risque global : {_score_label(result.overall_score)}",
                    textAnchor='middle', fontSize=13,
                    fontName='Helvetica-Bold', fillColor=col))
    e.append(label_d)
    e.append(Spacer(1, 1.8 * cm))

    # Metadata
    scan_date = result.timestamp.strftime('%d/%m/%Y à %H:%M')
    meta = [
        ['Date du scan',       scan_date],
        ['Référence',          result.scan_id[:22] + '…'],
        ['Modules analysés',   str(len(result.modules))],
        ['Score global',       f"{result.overall_score}/100 — {_score_label(result.overall_score)}"],
    ]
    mt = Table(meta, colWidths=[3.8 * cm, 9 * cm], hAlign='CENTER')
    mt.setStyle(TableStyle([
        ('FONTNAME',   (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME',   (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE',   (0, 0), (-1, -1), 9),
        ('TEXTCOLOR',  (0, 0), (0, -1), C_SUBTLE),
        ('TEXTCOLOR',  (1, 0), (1, -1), C_DARK),
        ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_LGREY, C_WHITE]),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
    ]))
    e.append(Table([[mt]], colWidths=[CW]))

    e.append(Spacer(1, 2.5 * cm))
    e.append(HRFlowable(width='100%', thickness=0.5, color=C_LGREY))
    e.append(Spacer(1, 0.3 * cm))
    e.append(Paragraph('Projet M1 Cybersécurité — ESGI 2025-2026 | Document Confidentiel',
                        S['center_sm']))
    e.append(PageBreak())
    return e


def _summary(result: ScanResult, S: dict) -> list:
    e = []
    e.append(Paragraph('Résumé Exécutif', S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_PURPLE, spaceAfter=10))

    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for m in result.modules:
        sev = m.severity.value
        if sev in counts:
            counts[sev] += 1

    e.append(_stat_boxes(counts))
    e.append(Spacer(1, 0.5 * cm))

    interp_map = [
        (40,  'La posture de sécurité est <b>critique</b>. Des actions immédiates sont requises.'),
        (60,  'La posture de sécurité présente des <b>risques élevés</b>. Des mesures correctives urgentes sont recommandées.'),
        (75,  'La posture de sécurité est <b>moyenne</b>. Plusieurs améliorations importantes sont à apporter.'),
        (85,  'La posture de sécurité est <b>bonne</b>. Quelques ajustements permettraient d\'atteindre l\'excellence.'),
        (101, 'La posture de sécurité est <b>excellente</b>. Continuez à maintenir ces bonnes pratiques.'),
    ]
    for threshold, text in interp_map:
        if result.overall_score < threshold:
            e.append(Paragraph(text, S['body']))
            break

    e.append(Spacer(1, 0.4 * cm))

    # Module overview table
    e.append(Paragraph("Vue d'ensemble des modules", S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_PURPLE, spaceAfter=8))

    rows = [['Module', 'Score', 'Niveau de risque', 'Statut']]
    for m in result.modules:
        rows.append([
            m.module_name,
            f'{m.score}/100',
            _sev_label(m.severity.value),
            _status_label(m.status),
        ])

    tbl = Table(rows, colWidths=[6.2 * cm, 2 * cm, 3.8 * cm, CW - 12 * cm])
    sev_styles = []
    for ri, m in enumerate(result.modules, 1):
        sev_styles += [
            ('TEXTCOLOR',  (2, ri), (2, ri), _sev_color(m.severity.value)),
            ('FONTNAME',   (2, ri), (2, ri), 'Helvetica-Bold'),
            ('TEXTCOLOR',  (1, ri), (1, ri), _score_color(m.score)),
            ('FONTNAME',   (1, ri), (1, ri), 'Helvetica-Bold'),
        ]
    tbl.setStyle(TableStyle([
        ('BACKGROUND',     (0, 0), (-1, 0),  C_PURPLE),
        ('TEXTCOLOR',      (0, 0), (-1, 0),  C_WHITE),
        ('FONTNAME',       (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',       (0, 0), (-1, -1), 9),
        ('ALIGN',          (1, 0), (-1, -1), 'CENTER'),
        ('VALIGN',         (0, 0), (-1, -1), 'MIDDLE'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_LGREY, C_WHITE]),
        ('TOPPADDING',     (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING',  (0, 0), (-1, -1), 6),
        ('LEFTPADDING',    (0, 0), (-1, -1), 8),
        ('RIGHTPADDING',   (0, 0), (-1, -1), 8),
        ('GRID',           (0, 0), (-1, -1), 0.3, colors.HexColor('#E5E7EB')),
    ] + sev_styles))
    e.append(tbl)
    e.append(Spacer(1, 0.5 * cm))

    # Bar chart
    e.append(Paragraph('Scores par module', S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_PURPLE, spaceAfter=8))
    bars = _draw_bars(result.modules)
    bt = Table([[bars]], colWidths=[CW])
    bt.setStyle(TableStyle([('ALIGN', (0, 0), (0, 0), 'CENTER')]))
    e.append(bt)

    e.append(PageBreak())
    return e


def _module_details(result: ScanResult, S: dict) -> list:
    e = []
    e.append(Paragraph('Analyse Détaillée par Module', S['h2']))
    e.append(HRFlowable(width='100%', thickness=1, color=C_PURPLE, spaceAfter=4))

    for m in result.modules:
        col = _score_color(m.score)
        sev_col = _sev_color(m.severity.value)
        block = []

        # Module header band
        hd = Drawing(CW, 1.3 * cm)
        bg = Rect(0, 0, CW, 1.3 * cm)
        bg.fillColor = C_LGREY
        bg.strokeColor = None
        hd.add(bg)
        left = Rect(0, 0, 0.35 * cm, 1.3 * cm)
        left.fillColor = col
        left.strokeColor = None
        hd.add(left)
        hd.add(RLS(0.6 * cm, 0.38 * cm, m.module_name,
                   fontSize=11, fontName='Helvetica-Bold', fillColor=C_DARK))
        hd.add(RLS(CW - 0.3 * cm, 0.65 * cm, f'{m.score}/100',
                   textAnchor='end', fontSize=13, fontName='Helvetica-Bold',
                   fillColor=col))
        hd.add(RLS(CW - 0.3 * cm, 0.18 * cm, _sev_label(m.severity.value),
                   textAnchor='end', fontSize=8, fontName='Helvetica-Bold',
                   fillColor=sev_col))
        block.append(hd)

        # Details table
        if m.details:
            detail_rows = []
            for k, v in m.details.items():
                if isinstance(v, list):
                    val_str = ', '.join(str(x) for x in v) if v else '—'
                elif isinstance(v, dict):
                    parts = [f"{dk}: {dv}" for dk, dv in v.items()]
                    val_str = ' | '.join(parts) if parts else '—'
                elif isinstance(v, bool):
                    val_str = 'Oui' if v else 'Non'
                else:
                    val_str = str(v) if v is not None else '—'
                if len(val_str) > 130:
                    val_str = val_str[:127] + '…'
                detail_rows.append([
                    k.replace('_', ' ').capitalize(),
                    Paragraph(val_str, S['small']),
                ])

            if detail_rows:
                dt = Table(detail_rows, colWidths=[3.5 * cm, CW - 3.5 * cm], hAlign='LEFT')
                dt.setStyle(TableStyle([
                    ('FONTNAME',       (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE',       (0, 0), (0, -1), 8),
                    ('TEXTCOLOR',      (0, 0), (0, -1), C_SUBTLE),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [C_WHITE, C_LGREY]),
                    ('TOPPADDING',     (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING',  (0, 0), (-1, -1), 4),
                    ('LEFTPADDING',    (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING',   (0, 0), (-1, -1), 8),
                    ('VALIGN',         (0, 0), (-1, -1), 'TOP'),
                    ('GRID',           (0, 0), (-1, -1), 0.3, colors.HexColor('#E5E7EB')),
                ]))
                block.append(Spacer(1, 0.15 * cm))
                block.append(dt)

        # Recommendations
        if m.recommendations:
            block.append(Spacer(1, 0.2 * cm))
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
    e.append(HRFlowable(width='100%', thickness=1, color=C_PURPLE, spaceAfter=6))
    e.append(Paragraph(
        'Les recommandations sont classées par priorité décroissante. '
        'Traitez en priorité les niveaux CRITIQUE et ÉLEVÉ.',
        S['body'],
    ))
    e.append(Spacer(1, 0.3 * cm))

    all_recs = sorted(
        [(m.severity.value, m.module_name, rec)
         for m in result.modules
         for rec in m.recommendations],
        key=lambda x: _sev_order(x[0]),
    )

    if not all_recs:
        e.append(Paragraph('Aucune recommandation — excellent résultat !', S['body']))
    else:
        rows = [['Priorité', 'Module', 'Recommandation']]
        for sev, module, rec in all_recs:
            rows.append([_sev_label(sev), module, Paragraph(rec, S['small'])])

        tbl = Table(rows, colWidths=[2.2 * cm, 4 * cm, CW - 6.2 * cm], repeatRows=1)
        sev_styles = []
        for ri, (sev, _, _) in enumerate(all_recs, 1):
            sev_styles += [
                ('TEXTCOLOR', (0, ri), (0, ri), _sev_color(sev)),
                ('FONTNAME',  (0, ri), (0, ri), 'Helvetica-Bold'),
            ]
        tbl.setStyle(TableStyle([
            ('BACKGROUND',     (0, 0), (-1, 0),  C_PURPLE),
            ('TEXTCOLOR',      (0, 0), (-1, 0),  C_WHITE),
            ('FONTNAME',       (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTSIZE',       (0, 0), (-1, -1), 8),
            ('ALIGN',          (0, 0), (1, -1),  'CENTER'),
            ('VALIGN',         (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [C_LGREY, C_WHITE]),
            ('TOPPADDING',     (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING',  (0, 0), (-1, -1), 5),
            ('LEFTPADDING',    (0, 0), (-1, -1), 6),
            ('RIGHTPADDING',   (0, 0), (-1, -1), 6),
            ('GRID',           (0, 0), (-1, -1), 0.3, colors.HexColor('#E5E7EB')),
        ] + sev_styles))
        e.append(tbl)

    e.append(Spacer(1, 1 * cm))
    e.append(HRFlowable(width='100%', thickness=0.5, color=C_LGREY))
    e.append(Spacer(1, 0.3 * cm))
    e.append(Paragraph(
        f"Rapport généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')} "
        f"par ÉON — ESGI 2025-2026",
        S['center_sm'],
    ))
    return e


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf(result: ScanResult) -> bytes:
    """Génère le rapport PDF complet et retourne les bytes."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
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
    doc.build(elements)
    return buf.getvalue()
