"""
Sentinel Fusion Model — XGBoost classifier trained on 6,700 TREC-2007 emails.
Trained on real email analysis outputs (125 features) from the full Sentinel pipeline.
Replaces the hand-crafted attention-weighted ensemble with a data-driven verdict.

Usage:
    from models.sentinel_fusion_model import predict_fusion, get_evaluation_metrics
    prob = predict_fusion(analysis_result)   # 0.0–1.0, -1 if unavailable
"""
import json
import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

_MODEL_PATH = Path(__file__).parent / "fusion_xgb.pkl"
_META_PATH  = Path(__file__).parent / "fusion_xgb_meta.json"

# ── Maps (must match build_dataset.py exactly) ────────────────────────────────
_TACTIC_LABEL_MAP = {
    "Urgency":                  "urgency",
    "Authority Impersonation":  "authority_impersonation",
    "Financial Lure":           "financial_lure",
    "Credential Harvesting":    "credential_harvesting",
    "Suspicious Link":          "suspicious_link",
    "Fear / Threat":            "fear_threat",
    "Fear/Threat":              "fear_threat",
    "Spoofing":                 "spoofing",
    "Reward Framing":           "reward_framing",
    "BEC Pattern":              "bec_pattern",
    "Executive Impersonation":  "executive_impersonation",
}
_TACTIC_NAMES = list(dict.fromkeys(_TACTIC_LABEL_MAP.values()))

_SPF_MAP   = {"pass": 1, "fail": -1, "softfail": -1, "unknown": 0}
_DKIM_MAP  = {"pass": 1, "fail": -1, "none": 0,      "unknown": 0}
_DMARC_MAP = {"pass": 1, "fail": -1, "none": 0}

_VERDICT_MAP = {
    "SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2, "CRITICAL": 3,
    "CONFIRMED_THREAT": 3, "UNKNOWN": -1,
}
_DARK_WEB_MAP = {"NONE": 0, "UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_IMPACT_MAP   = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
_ACTION_MAP   = {
    "monitor": 0, "flag_for_review": 1,
    "quarantine_and_block": 2, "quarantine_block_and_alert": 3,
}
_NLP_SOURCE_MAP = {
    "openrouter_gpt4o_mini": 0, "ensemble_gpt4o_mini_bert": 1,
    "bert_heuristic_blend": 2,  "heuristic_fallback": 3, "unknown": -1,
}
_ATTACK_VEC_MAP = {
    "Email-based Phishing":              0,
    "Social Engineering — Urgency/Fear": 1,
    "Sender Spoofing":                   2,
}

# Feature order must match training exactly (from fusion_xgb_meta.json)
_FEATURE_COLS: Optional[list] = None


# ── Load model ────────────────────────────────────────────────────────────────
_model = None
_meta: Optional[dict] = None


def _load():
    global _model, _meta, _FEATURE_COLS
    try:
        if not _MODEL_PATH.exists():
            logger.warning(f"[FusionXGB] Model not found: {_MODEL_PATH}")
            return
        with open(_MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        if _META_PATH.exists():
            with open(_META_PATH) as f:
                _meta = json.load(f)
            _FEATURE_COLS = _meta.get("features", [])
        logger.info(
            f"[FusionXGB] Loaded — {_meta.get('n_features')} features, "
            f"test F1={_meta.get('test_metrics', {}).get('f1_score')}, "
            f"AUC={_meta.get('test_metrics', {}).get('roc_auc')}"
        )
    except Exception as e:
        logger.warning(f"[FusionXGB] Load failed: {e}")


_load()


# ── Feature extraction (mirrors build_dataset.py:extract_features) ────────────
def _extract(r: dict) -> Optional[np.ndarray]:
    if not _FEATURE_COLS:
        return None
    try:
        mb        = r.get("model_breakdown", {})
        nlp       = mb.get("nlp",    {})
        url_b     = mb.get("url",    {})
        hdr       = mb.get("header", {})
        ti        = r.get("threat_intelligence", {}) or {}
        ioc       = r.get("ioc_enrichment", {}) or {}
        dw        = r.get("dark_web_exposure", {}) or {}
        kc        = r.get("kill_chain") or {}
        kc_stages = kc.get("kill_chain_stages", [])

        tactic_conf = {}
        for t in r.get("detected_tactics", []):
            key = _TACTIC_LABEL_MAP.get(t.get("name", ""))
            if key:
                tactic_conf[key] = round(float(t.get("confidence", 0)), 4)

        shap      = url_b.get("shap_values", {}) or {}
        raw_feats = url_b.get("features", {}) or {}
        flags     = hdr.get("flags", []) or []
        spf_raw   = hdr.get("spf_result",  "unknown")
        dkim_raw  = hdr.get("dkim_result", "unknown")
        dmarc_raw = hdr.get("dmarc_result", "none")

        stage_risks = {s["phase"]: round(float(s.get("risk_score", 0)), 4) for s in kc_stages}
        impact      = kc.get("estimated_impact", {}) or {}
        atk_vec     = kc.get("attack_vector", "Unknown")

        row = {
            "verdict_encoded":               _VERDICT_MAP.get(r.get("verdict", "UNKNOWN"), -1),
            "inference_time_ms":             r.get("inference_time_ms", 0),
            "threat_score":                  round(float(r.get("threat_score", 0)), 6),
            "confidence":                    round(float(r.get("confidence", 0)), 6),
            "recommended_action_encoded":    _ACTION_MAP.get(r.get("recommended_action", ""), -1),
            "nlp_score":                     round(float(nlp.get("score", 0)), 6),
            "nlp_weight":                    round(float(nlp.get("weight", 0)), 4),
            "nlp_source_encoded":            _NLP_SOURCE_MAP.get(nlp.get("source") or "unknown", -1),
            "top_phrase_count":              len(nlp.get("top_phrases", []) or []),
            "tactic_count":                  len(tactic_conf),
            **{f"tactic_{t}":               tactic_conf.get(t, 0) for t in _TACTIC_NAMES},
            "url_score":                     round(float(url_b.get("score", 0)), 6),
            "url_weight":                    round(float(url_b.get("weight", 0)), 4),
            "url_count":                     len(r.get("urls_analyzed", [])),
            "shap_ip_as_host":               shap.get("ip_as_host", 0),
            "shap_brand_impersonation":      shap.get("brand_impersonation", 0),
            "shap_auth_in_domain":           shap.get("auth_in_domain", 0),
            "shap_high_risk_tld":            shap.get("high_risk_tld", 0),
            "shap_newly_registered":         shap.get("newly_registered", 0),
            "shap_no_ssl":                   shap.get("no_ssl", 0),
            "shap_url_length_long":          shap.get("url_length_long", 0),
            "shap_url_length_very_long":     shap.get("url_length_very_long", 0),
            "shap_subdomain_abuse":          shap.get("subdomain_abuse", 0),
            "shap_high_entropy":             shap.get("high_entropy_domain", 0),
            "shap_typosquatting":            shap.get("typosquatting", 0),
            "shap_brand_in_path":            shap.get("brand_in_path", 0),
            "shap_suspicious_keywords":      shap.get("suspicious_keywords", 0),
            "shap_hex_encoding":             shap.get("hex_encoding", 0),
            "shap_at_symbol":                shap.get("at_symbol", 0),
            "shap_redirect_pattern":         shap.get("redirect_pattern", 0),
            "shap_exe_extension":            shap.get("exe_extension", 0),
            "shap_medium_risk_tld":          shap.get("medium_risk_tld", 0),
            "shap_excessive_hyphens":        shap.get("excessive_hyphens", 0),
            "shap_double_slash":             shap.get("double_slash", 0),
            "shap_privacy_protected":        shap.get("privacy_protected", 0),
            "shap_no_dns_record":            shap.get("no_dns_record", 0),
            "shap_no_spf":                   shap.get("no_spf", 0),
            "shap_no_dmarc":                 shap.get("no_dmarc", 0),
            "shap_urlhaus_hit":              shap.get("known_malicious_urlhaus", 0),
            "url_length":                    raw_feats.get("url_length", 0),
            "domain_length":                 raw_feats.get("domain_length", 0),
            "path_length":                   raw_feats.get("path_length", 0),
            "query_length":                  raw_feats.get("query_length", 0),
            "num_dots":                      raw_feats.get("num_dots", 0),
            "num_hyphens":                   raw_feats.get("num_hyphens", 0),
            "num_underscores":               raw_feats.get("num_underscores", 0),
            "num_slashes":                   raw_feats.get("num_slashes", 0),
            "num_at":                        raw_feats.get("num_at", 0),
            "num_question":                  raw_feats.get("num_question", 0),
            "num_equals":                    raw_feats.get("num_equals", 0),
            "num_ampersand":                 raw_feats.get("num_ampersand", 0),
            "num_percent":                   raw_feats.get("num_percent", 0),
            "url_entropy":                   round(float(raw_feats.get("url_entropy", 0)), 4),
            "domain_entropy":                round(float(raw_feats.get("domain_entropy", 0)), 4),
            "subdomain_count":               raw_feats.get("subdomain_count", 0),
            "subdomain_length":              raw_feats.get("subdomain_length", 0),
            "path_depth":                    raw_feats.get("path_depth", 0),
            "has_ip_address":                int(bool(raw_feats.get("has_ip_address", 0))),
            "is_https":                      int(bool(raw_feats.get("is_https", 0))),
            "is_http":                       int(bool(raw_feats.get("is_http", 0))),
            "tld_risk_high":                 int(bool(raw_feats.get("tld_risk_high", 0))),
            "tld_risk_medium":               int(bool(raw_feats.get("tld_risk_medium", 0))),
            "brand_in_domain":               int(bool(raw_feats.get("brand_in_domain", 0))),
            "brand_in_path":                 int(bool(raw_feats.get("brand_in_path", 0))),
            "is_legitimate_host":            int(bool(raw_feats.get("is_legitimate_host", 0))),
            "typosquatting_score":           round(float(raw_feats.get("typosquatting_score", 0)), 4),
            "suspicious_path_kw":            raw_feats.get("suspicious_path_kw", 0),
            "suspicious_domain_kw":          raw_feats.get("suspicious_domain_kw", 0),
            "has_exe_extension":             int(bool(raw_feats.get("has_exe_extension", 0))),
            "has_file_extension":            int(bool(raw_feats.get("has_file_extension", 0))),
            "has_hex_encoding":              int(bool(raw_feats.get("has_hex_encoding", 0))),
            "double_slash_in_path":          int(bool(raw_feats.get("double_slash_in_path", 0))),
            "has_at_symbol":                 int(bool(raw_feats.get("has_at_symbol", 0))),
            "redirects_in_url":              int(bool(raw_feats.get("redirects_in_url", 0))),
            "domain_has_numbers":            int(bool(raw_feats.get("domain_has_numbers", 0))),
            "domain_has_hyphens":            int(bool(raw_feats.get("domain_has_hyphens", 0))),
            "header_score":                  round(float(hdr.get("score", 0)), 6),
            "header_weight":                 round(float(hdr.get("weight", 0)), 4),
            "header_flag_count":             len(flags),
            "spf_result":                    _SPF_MAP.get(spf_raw, 0),
            "dkim_result":                   _DKIM_MAP.get(dkim_raw, 0),
            "dmarc_result":                  _DMARC_MAP.get(dmarc_raw, 0),
            "flag_spf_fail":                 int("spf_fail" in flags),
            "flag_dkim_fail":                int("dkim_fail" in flags),
            "flag_dkim_missing":             int("dkim_missing" in flags),
            "flag_dmarc_fail":               int("dmarc_fail" in flags),
            "flag_reply_to_mismatch":        int("reply_to_mismatch" in flags),
            "flag_return_path_mismatch":     int("return_path_mismatch" in flags),
            "flag_bulk_mailer":              int("bulk_mailer_detected" in flags),
            "flag_missing_message_id":       int("missing_message_id" in flags),
            "flag_missing_date":             int("missing_date_header" in flags),
            "flag_excessive_hops":           int("excessive_routing_hops" in flags),
            "has_known_campaign":            int(ti.get("campaign_id", "Unknown") != "Unknown"),
            "actor_confidence":              round(float(ti.get("actor_confidence", 0)), 4),
            "related_domains_count":         len(ti.get("related_domains", [])),
            "ti_malicious_domain_count":     len(ti.get("malicious_domains", [])),
            "ti_feed_source_count":          len(ti.get("feed_sources", [])),
            "ti_global_reach_count":         len(ti.get("global_reach", [])),
            "ioc_risk_boost":                round(float(ioc.get("risk_boost", 0)), 4),
            "ioc_malicious_domain_count":    len(ioc.get("malicious_domains", [])),
            "ioc_malicious_ip_count":        len(ioc.get("malicious_ips", [])),
            "ioc_threat_family_count":       len(ioc.get("threat_families", [])),
            "ioc_source_count":              len(ioc.get("sources", [])),
            "dark_web_risk":                 _DARK_WEB_MAP.get(dw.get("dark_web_risk", "UNKNOWN"), 0),
            "dark_web_breach_count":         dw.get("breach_count", 0),
            "dark_web_total_exposed":        dw.get("total_exposed", 0),
            "dark_web_source_count":         len(dw.get("sources", [])),
            "kill_chain_active_stages":      kc.get("active_stage_count", 0),
            "kill_chain_overall_risk":       round(float(kc.get("overall_risk", 0)), 4) if kc.get("overall_risk") else 0,
            "kill_chain_attack_vector_encoded": _ATTACK_VEC_MAP.get(
                atk_vec, 3 if "Brand Impersonation" in atk_vec else -1
            ),
            "kill_chain_is_brand_impersonation": int("Brand Impersonation" in atk_vec),
            "kill_chain_initial_access_risk":    stage_risks.get("Initial Access", 0),
            "kill_chain_credential_risk":        stage_risks.get("Credential Access", 0),
            "kill_chain_financial_risk":         stage_risks.get("Financial Impact", 0),
            "kill_chain_lateral_risk":           stage_risks.get("Lateral Movement", 0),
            "kill_chain_impact_level":           _IMPACT_MAP.get(impact.get("level", "LOW"), 0),
        }

        vec = np.array([float(row.get(col, 0)) for col in _FEATURE_COLS], dtype=np.float32)
        return vec

    except Exception as e:
        logger.debug(f"[FusionXGB] Feature extraction error: {e}")
        return None


# ── Public API ─────────────────────────────────────────────────────────────────

def predict_fusion(result: dict) -> float:
    """
    Return calibrated phishing probability (0.0–1.0) for a full analysis result.
    Returns -1.0 if the model is unavailable or feature extraction fails.
    """
    if _model is None:
        return -1.0
    try:
        vec = _extract(result)
        if vec is None:
            return -1.0
        prob = float(_model.predict_proba(vec.reshape(1, -1))[0][1])
        return round(prob, 4)
    except Exception as e:
        logger.debug(f"[FusionXGB] Prediction error: {e}")
        return -1.0


def get_evaluation_metrics() -> dict:
    """Return test-set evaluation metrics for the trained fusion model."""
    if _meta is None:
        return {"error": "Fusion XGBoost model not loaded", "model": "XGBClassifier"}
    return {
        **_meta.get("test_metrics", {}),
        "model":          "XGBClassifier (SentinelFusion)",
        "train_size":     _meta.get("train_size"),
        "val_size":       _meta.get("val_size"),
        "test_size":      _meta.get("test_size"),
        "n_features":     _meta.get("n_features"),
        "top_features":   _meta.get("top_features", [])[:10],
        "dataset":        "TREC-2007 (6,700 emails — 5,182 spam / 1,518 ham)",
        "split":          "70% train / 15% val / 15% test (stratified)",
        "note":           "Trained on Sentinel pipeline outputs; calibrates the full ensemble",
    }
