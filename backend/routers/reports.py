"""
Report generation endpoints — PDF incident reports for analysis results.
Uses ReportLab for PDF generation with SentinelAI branding.
"""
import io
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["reports"])


class ReportRequest(BaseModel):
    event_id: Optional[str] = None
    analysis_result: Optional[dict] = None  # Full result object (if event_id not in cache)
    analyst_name: Optional[str] = "Security Analyst"
    include_iocs: Optional[bool] = True
    include_mitre: Optional[bool] = True


def _generate_pdf_report(data: dict, analyst_name: str, include_iocs: bool, include_mitre: bool) -> bytes:
    """Generate a PDF incident report using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether,
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        raise HTTPException(status_code=503, detail="reportlab not installed. Run: pip install reportlab")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=1 * inch,
        rightMargin=1 * inch,
    )

    styles = getSampleStyleSheet()
    # Custom styles
    title_style = ParagraphStyle("Title", parent=styles["Heading1"], fontSize=20, textColor=colors.HexColor("#1e3a5f"), spaceAfter=6)
    heading_style = ParagraphStyle("Heading", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1e3a5f"), spaceBefore=12, spaceAfter=4)
    normal_style = ParagraphStyle("Normal", parent=styles["Normal"], fontSize=10, spaceAfter=3)
    label_style = ParagraphStyle("Label", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#666666"))
    critical_style = ParagraphStyle("Critical", parent=styles["Normal"], fontSize=11, textColor=colors.HexColor("#dc2626"), fontName="Helvetica-Bold")
    safe_style = ParagraphStyle("Safe", parent=styles["Normal"], fontSize=11, textColor=colors.HexColor("#16a34a"), fontName="Helvetica-Bold")

    # Color by verdict
    verdict = data.get("verdict", "UNKNOWN")
    threat_score = data.get("threat_score", 0.0)
    verdict_color = {
        "CRITICAL": colors.HexColor("#dc2626"),
        "PHISHING": colors.HexColor("#ea580c"),
        "SUSPICIOUS": colors.HexColor("#d97706"),
        "SAFE": colors.HexColor("#16a34a"),
    }.get(verdict, colors.HexColor("#6b7280"))

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("SentinelAI Fusion", title_style))
    story.append(Paragraph("Threat Detection Incident Report", ParagraphStyle("Sub", parent=styles["Normal"], fontSize=12, textColor=colors.HexColor("#6b7280"), spaceAfter=4)))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e3a5f"), spaceAfter=8))

    # Meta row
    now = datetime.utcnow().isoformat() + "Z"
    meta = [
        ["Event ID", data.get("event_id", "N/A"), "Report Time", now[:19] + "Z"],
        ["Analyst", analyst_name, "Status", data.get("status", "completed").upper()],
    ]
    meta_table = Table(meta, colWidths=[1.2 * inch, 2.5 * inch, 1.2 * inch, 2.5 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#6b7280")),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("FONTNAME", (3, 0), (3, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # ── Verdict Banner ────────────────────────────────────────────────────────
    story.append(Paragraph("DETECTION VERDICT", heading_style))
    verdict_data = [
        ["Verdict", "Threat Score", "Confidence", "Inference Time"],
        [
            verdict,
            f"{round(threat_score * 100, 1)}%",
            f"{round(data.get('confidence', 0) * 100, 1)}%",
            f"{data.get('inference_time_ms', 0)}ms",
        ],
    ]
    vt = Table(verdict_data, colWidths=[1.8 * inch, 1.8 * inch, 1.8 * inch, 1.8 * inch])
    vt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BACKGROUND", (0, 1), (0, 1), verdict_color),
        ("TEXTCOLOR", (0, 1), (0, 1), colors.white),
        ("FONTNAME", (0, 1), (0, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 1), (0, 1), 13),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(vt)
    story.append(Spacer(1, 10))

    # ── Model Breakdown ───────────────────────────────────────────────────────
    story.append(Paragraph("AI MODEL BREAKDOWN", heading_style))
    breakdown = data.get("model_breakdown", {})
    model_rows = [["Model", "Score", "Weight", "Key Findings"]]

    for model_name, model_data in breakdown.items():
        score = model_data.get("score", 0.0)
        weight = model_data.get("weight", 0.0)
        if model_name == "nlp":
            findings = "; ".join(model_data.get("tactics", [])[:3]) or "No tactics detected"
        elif model_name == "url":
            findings = ", ".join(model_data.get("top_features", [])[:3]) or "No features flagged"
        elif model_name == "visual":
            brand = model_data.get("matched_brand", "Unknown")
            sim = model_data.get("similarity", 0.0)
            findings = f"Brand: {brand} ({round(sim*100,1)}% similarity)"
        elif model_name == "header":
            flags = model_data.get("flags", [])
            findings = ", ".join(flags[:3]) if flags else "No header anomalies"
        else:
            findings = ""

        model_rows.append([
            model_name.upper(),
            f"{round(score * 100, 1)}%",
            f"{round(weight * 100, 0):.0f}%",
            findings,
        ])

    mt = Table(model_rows, colWidths=[1.0 * inch, 0.9 * inch, 0.9 * inch, 4.6 * inch])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (2, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(mt)
    story.append(Spacer(1, 10))

    # ── Threat Intelligence ───────────────────────────────────────────────────
    intel = data.get("threat_intelligence", {})
    if intel.get("campaign_id") != "Unknown" or intel.get("threat_actor") != "Unknown":
        story.append(Paragraph("THREAT INTELLIGENCE ATTRIBUTION", heading_style))
        intel_rows = [
            ["Campaign ID", intel.get("campaign_id", "Unknown")],
            ["Threat Actor", intel.get("threat_actor", "Unknown")],
            ["Actor Confidence", f"{round(intel.get('actor_confidence', 0)*100, 1)}%"],
            ["Global Reach", ", ".join(intel.get("global_reach", [])) or "Unknown"],
        ]
        if intel.get("malicious_domains"):
            intel_rows.append(["Malicious Domains", ", ".join(intel["malicious_domains"][:5])])
        if intel.get("feed_sources"):
            intel_rows.append(["Intel Sources", ", ".join(intel["feed_sources"])])

        it = Table(intel_rows, colWidths=[2.0 * inch, 5.4 * inch])
        it.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(it)
        story.append(Spacer(1, 10))

    # ── Detected Tactics ─────────────────────────────────────────────────────
    tactics = data.get("detected_tactics", [])
    if tactics and include_mitre:
        story.append(Paragraph("DETECTED MITRE ATT&CK TACTICS", heading_style))
        tactic_rows = [["Tactic", "MITRE ID", "Confidence"]]
        for t in tactics[:10]:
            tactic_rows.append([
                t.get("name", "Unknown"),
                t.get("mitre_id", "N/A"),
                f"{round(t.get('confidence', 0)*100, 1)}%",
            ])
        tt = Table(tactic_rows, colWidths=[3.5 * inch, 1.8 * inch, 1.8 * inch])
        tt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e5e7eb")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(tt)
        story.append(Spacer(1, 10))

    # ── IOC Summary ──────────────────────────────────────────────────────────
    if include_iocs:
        urls = data.get("urls_analyzed", [])
        ioc = data.get("ioc_enrichment", {})
        malicious_domains = ioc.get("malicious_domains", [])

        if urls or malicious_domains:
            story.append(Paragraph("INDICATORS OF COMPROMISE (IOCs)", heading_style))
            if urls:
                for url in urls[:5]:
                    story.append(Paragraph(f"• URL: {url}", normal_style))
            if malicious_domains:
                for domain in malicious_domains[:5]:
                    story.append(Paragraph(f"• Malicious Domain (confirmed): {domain}", critical_style))

    # ── Explanation Narrative ─────────────────────────────────────────────────
    narrative = data.get("explanation_narrative", "")
    if narrative:
        story.append(Paragraph("ANALYST NARRATIVE", heading_style))
        story.append(Paragraph(narrative[:1500], normal_style))

    # ── Recommended Action ────────────────────────────────────────────────────
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e5e7eb"), spaceAfter=6))
    action = data.get("recommended_action", "monitor")
    story.append(Paragraph(f"RECOMMENDED ACTION: {action.upper().replace('_', ' ')}", heading_style))

    # Footer
    story.append(Spacer(1, 20))
    story.append(Paragraph(
        f"Generated by SentinelAI Fusion v1.0 • {now} • Confidential",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.HexColor("#9ca3af"), alignment=TA_CENTER),
    ))

    doc.build(story)
    return buffer.getvalue()


def _generate_text_fallback(data: dict, analyst_name: str) -> bytes:
    """Text fallback report when ReportLab is unavailable."""
    verdict = data.get("verdict", "UNKNOWN")
    score = round(data.get("threat_score", 0) * 100, 1)
    lines = [
        "=" * 60,
        "SENTINELAI FUSION — INCIDENT REPORT",
        "=" * 60,
        f"Event ID:     {data.get('event_id', 'N/A')}",
        f"Analyst:      {analyst_name}",
        f"Generated:    {datetime.utcnow().isoformat()}Z",
        f"Verdict:      {verdict}",
        f"Threat Score: {score}%",
        f"Confidence:   {round(data.get('confidence', 0)*100,1)}%",
        "",
        "THREAT INTELLIGENCE",
        "-" * 40,
    ]
    intel = data.get("threat_intelligence", {})
    lines.append(f"Campaign:     {intel.get('campaign_id', 'Unknown')}")
    lines.append(f"Actor:        {intel.get('threat_actor', 'Unknown')}")
    lines.append(f"Attribution:  {round(intel.get('actor_confidence', 0)*100,1)}%")
    lines.append("")
    lines.append("DETECTED TACTICS")
    lines.append("-" * 40)
    for t in data.get("detected_tactics", []):
        lines.append(f"  [{t.get('mitre_id','N/A')}] {t.get('name','')}")
    lines.append("")
    lines.append("RECOMMENDED ACTION")
    lines.append("-" * 40)
    lines.append(f"  {data.get('recommended_action', 'monitor').upper()}")
    lines.append("")
    narrative = data.get("explanation_narrative", "")
    if narrative:
        lines.append("ANALYST NARRATIVE")
        lines.append("-" * 40)
        lines.append(narrative[:800])
    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines).encode("utf-8")


@router.post("/reports/generate")
async def generate_report(request: ReportRequest):
    """
    Generate a PDF incident report for an analysis result.
    If event_id provided, fetches from cache. Otherwise uses analysis_result directly.
    Returns the PDF as a streaming download.
    """
    # Get analysis data
    if request.event_id:
        from routers.analyze import _result_cache
        data = _result_cache.get(request.event_id)
        if not data:
            raise HTTPException(status_code=404, detail=f"Event {request.event_id} not found. Results expire after 500 scans.")
    elif request.analysis_result:
        data = request.analysis_result
    else:
        raise HTTPException(status_code=400, detail="Either event_id or analysis_result is required.")

    event_id = data.get("event_id", "unknown")
    verdict = data.get("verdict", "UNKNOWN")
    filename = f"sentinel_report_{event_id}_{verdict.lower()}.pdf"

    try:
        pdf_bytes = _generate_pdf_report(
            data=data,
            analyst_name=request.analyst_name or "Security Analyst",
            include_iocs=request.include_iocs if request.include_iocs is not None else True,
            include_mitre=request.include_mitre if request.include_mitre is not None else True,
        )
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"[Reports] PDF generation failed ({e}), using text fallback")
        # Fallback to plain text
        text_bytes = _generate_text_fallback(data, request.analyst_name or "Security Analyst")
        txt_filename = filename.replace(".pdf", ".txt")
        return StreamingResponse(
            io.BytesIO(text_bytes),
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{txt_filename}"'},
        )


@router.get("/reports/preview/{event_id}")
async def preview_report_data(event_id: str):
    """Preview the data that would be included in a report (without PDF generation)."""
    from routers.analyze import _result_cache
    data = _result_cache.get(event_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")
    return {
        "event_id": event_id,
        "report_sections": [
            "verdict_banner",
            "model_breakdown",
            "threat_intelligence",
            "detected_tactics" if data.get("detected_tactics") else None,
            "ioc_summary" if data.get("urls_analyzed") else None,
            "explanation_narrative" if data.get("explanation_narrative") else None,
        ],
        "metadata": {
            "verdict": data.get("verdict"),
            "threat_score": data.get("threat_score"),
            "event_id": event_id,
            "timestamp": data.get("timestamp"),
        },
    }
