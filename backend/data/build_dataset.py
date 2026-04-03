"""
Dataset builder — TREC-2007 (email_origin.csv) → sentinel_dataset.csv
- Checkpoints every 50 rows (safe against crashes / credit exhaustion)
- Resume from last checkpoint on restart
- Retries with backoff on API errors
- Progress log to build_dataset.log
"""
import os
import time
import logging
import requests
import pandas as pd
from datetime import datetime

API        = "http://localhost:8001"
INPUT_CSV  = "/root/sent/sentinel/backend/data/email_origin.csv"
OUTPUT_CSV = "/root/sent/sentinel/backend/data/sentinel_dataset.csv"
LOG_FILE   = "/root/sent/sentinel/backend/data/build_dataset.log"
CHECKPOINT_EVERY = 50    # save to CSV every N rows
MAX_RETRIES      = 3    # retries per email on API error
RETRY_DELAY      = 5    # seconds between retries
REQUEST_DELAY    = 0.3  # seconds between requests (avoid hammering backend)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger()

# ── Maps ──────────────────────────────────────────────────────────────────────
TACTIC_LABEL_MAP = {
    "Urgency":                    "urgency",
    "Authority Impersonation":    "authority_impersonation",
    "Financial Lure":             "financial_lure",
    "Credential Harvesting":      "credential_harvesting",
    "Suspicious Link":            "suspicious_link",
    "Fear / Threat":              "fear_threat",
    "Fear/Threat":                "fear_threat",
    "Spoofing":                   "spoofing",
    "Reward Framing":             "reward_framing",
    "BEC Pattern":                "bec_pattern",
    "Executive Impersonation":    "executive_impersonation",
}
TACTIC_NAMES = list(dict.fromkeys(TACTIC_LABEL_MAP.values()))

SPF_MAP   = {"pass": 1, "fail": -1, "softfail": -1, "unknown": 0}
DKIM_MAP  = {"pass": 1, "fail": -1, "none": 0,      "unknown": 0}
DMARC_MAP = {"pass": 1, "fail": -1, "none": 0}

VERDICT_MAP = {"SAFE": 0, "SUSPICIOUS": 1, "PHISHING": 2, "CRITICAL": 3,
               "CONFIRMED_THREAT": 3, "UNKNOWN": -1}
DARK_WEB_MAP = {"NONE": 0, "UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
IMPACT_MAP   = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
ACTION_MAP   = {"monitor": 0, "flag_for_review": 1,
                "quarantine_and_block": 2, "quarantine_block_and_alert": 3}
NLP_SOURCE_MAP = {
    "openrouter_gpt4o_mini": 0, "ensemble_gpt4o_mini_bert": 1,
    "bert_heuristic_blend": 2,  "heuristic_fallback": 3, "unknown": -1,
}
ATTACK_VEC_MAP = {
    "Email-based Phishing":              0,
    "Social Engineering — Urgency/Fear": 1,
    "Sender Spoofing":                   2,
}

# ── Feature extractor ─────────────────────────────────────────────────────────
def extract_features(r: dict, label: int) -> dict:
    mb        = r.get("model_breakdown", {})
    nlp       = mb.get("nlp",    {})
    url_b     = mb.get("url",    {})
    hdr       = mb.get("header", {})
    ti        = r.get("threat_intelligence", {})
    ioc       = r.get("ioc_enrichment", {}) or {}
    dw        = r.get("dark_web_exposure", {}) or {}
    kc        = r.get("kill_chain") or {}
    kc_stages = kc.get("kill_chain_stages", [])

    tactic_conf = {}
    for t in r.get("detected_tactics", []):
        key = TACTIC_LABEL_MAP.get(t["name"])
        if key:
            tactic_conf[key] = round(t["confidence"], 4)

    shap      = url_b.get("shap_values", {})
    raw_feats = url_b.get("features", {}) or {}
    flags     = hdr.get("flags", []) or []
    spf_raw   = hdr.get("spf_result",  "unknown")
    dkim_raw  = hdr.get("dkim_result", "unknown")
    dmarc_raw = hdr.get("dmarc_result","none")

    stage_risks = {s["phase"]: round(s.get("risk_score", 0), 4) for s in kc_stages}
    impact      = kc.get("estimated_impact", {}) or {}
    atk_vec     = kc.get("attack_vector", "Unknown")

    return {
        # Meta
        "label":                             label,
        "verdict":                           r.get("verdict", "UNKNOWN"),
        "verdict_encoded":                   VERDICT_MAP.get(r.get("verdict", "UNKNOWN"), -1),
        "input_type":                        r.get("input_type", "email"),
        "inference_time_ms":                 r.get("inference_time_ms", 0),
        # Fusion
        "threat_score":                      round(r.get("threat_score", 0), 6),
        "confidence":                        round(r.get("confidence", 0), 6),
        "recommended_action":                r.get("recommended_action", "unknown"),
        "recommended_action_encoded":        ACTION_MAP.get(r.get("recommended_action", ""), -1),
        # NLP
        "nlp_score":                         round(nlp.get("score", 0), 6),
        "nlp_weight":                        round(nlp.get("weight", 0), 4),
        "nlp_source":                        nlp.get("source") or "unknown",
        "nlp_source_encoded":                NLP_SOURCE_MAP.get(nlp.get("source") or "unknown", -1),
        "top_phrase_count":                  len(nlp.get("top_phrases", []) or []),
        "tactic_count":                      len(tactic_conf),
        **{f"tactic_{t}":                    tactic_conf.get(t, 0) for t in TACTIC_NAMES},
        # URL scores
        "url_score":                         round(url_b.get("score", 0), 6),
        "url_weight":                        round(url_b.get("weight", 0), 4),
        "url_count":                         len(r.get("urls_analyzed", [])),
        # SHAP
        "shap_ip_as_host":                   shap.get("ip_as_host", 0),
        "shap_brand_impersonation":          shap.get("brand_impersonation", 0),
        "shap_auth_in_domain":               shap.get("auth_in_domain", 0),
        "shap_high_risk_tld":                shap.get("high_risk_tld", 0),
        "shap_newly_registered":             shap.get("newly_registered", 0),
        "shap_no_ssl":                       shap.get("no_ssl", 0),
        "shap_url_length_long":              shap.get("url_length_long", 0),
        "shap_url_length_very_long":         shap.get("url_length_very_long", 0),
        "shap_subdomain_abuse":              shap.get("subdomain_abuse", 0),
        "shap_high_entropy":                 shap.get("high_entropy_domain", 0),
        "shap_typosquatting":                shap.get("typosquatting", 0),
        "shap_brand_in_path":                shap.get("brand_in_path", 0),
        "shap_suspicious_keywords":          shap.get("suspicious_keywords", 0),
        "shap_hex_encoding":                 shap.get("hex_encoding", 0),
        "shap_at_symbol":                    shap.get("at_symbol", 0),
        "shap_redirect_pattern":             shap.get("redirect_pattern", 0),
        "shap_exe_extension":                shap.get("exe_extension", 0),
        "shap_medium_risk_tld":              shap.get("medium_risk_tld", 0),
        "shap_excessive_hyphens":            shap.get("excessive_hyphens", 0),
        "shap_double_slash":                 shap.get("double_slash", 0),
        "shap_privacy_protected":            shap.get("privacy_protected", 0),
        "shap_no_dns_record":                shap.get("no_dns_record", 0),
        "shap_no_spf":                       shap.get("no_spf", 0),
        "shap_no_dmarc":                     shap.get("no_dmarc", 0),
        "shap_urlhaus_hit":                  shap.get("known_malicious_urlhaus", 0),
        # URL lexical
        "url_length":                        raw_feats.get("url_length", 0),
        "domain_length":                     raw_feats.get("domain_length", 0),
        "path_length":                       raw_feats.get("path_length", 0),
        "query_length":                      raw_feats.get("query_length", 0),
        "num_dots":                          raw_feats.get("num_dots", 0),
        "num_hyphens":                       raw_feats.get("num_hyphens", 0),
        "num_underscores":                   raw_feats.get("num_underscores", 0),
        "num_slashes":                       raw_feats.get("num_slashes", 0),
        "num_at":                            raw_feats.get("num_at", 0),
        "num_question":                      raw_feats.get("num_question", 0),
        "num_equals":                        raw_feats.get("num_equals", 0),
        "num_ampersand":                     raw_feats.get("num_ampersand", 0),
        "num_percent":                       raw_feats.get("num_percent", 0),
        "url_entropy":                       round(float(raw_feats.get("url_entropy", 0)), 4),
        "domain_entropy":                    round(float(raw_feats.get("domain_entropy", 0)), 4),
        "subdomain_count":                   raw_feats.get("subdomain_count", 0),
        "subdomain_length":                  raw_feats.get("subdomain_length", 0),
        "path_depth":                        raw_feats.get("path_depth", 0),
        "has_ip_address":                    int(bool(raw_feats.get("has_ip_address", 0))),
        "is_https":                          int(bool(raw_feats.get("is_https", 0))),
        "is_http":                           int(bool(raw_feats.get("is_http", 0))),
        "tld_risk_high":                     int(bool(raw_feats.get("tld_risk_high", 0))),
        "tld_risk_medium":                   int(bool(raw_feats.get("tld_risk_medium", 0))),
        "brand_in_domain":                   int(bool(raw_feats.get("brand_in_domain", 0))),
        "brand_in_path":                     int(bool(raw_feats.get("brand_in_path", 0))),
        "is_legitimate_host":                int(bool(raw_feats.get("is_legitimate_host", 0))),
        "typosquatting_score":               round(float(raw_feats.get("typosquatting_score", 0)), 4),
        "suspicious_path_kw":                raw_feats.get("suspicious_path_kw", 0),
        "suspicious_domain_kw":              raw_feats.get("suspicious_domain_kw", 0),
        "has_exe_extension":                 int(bool(raw_feats.get("has_exe_extension", 0))),
        "has_file_extension":                int(bool(raw_feats.get("has_file_extension", 0))),
        "has_hex_encoding":                  int(bool(raw_feats.get("has_hex_encoding", 0))),
        "double_slash_in_path":              int(bool(raw_feats.get("double_slash_in_path", 0))),
        "has_at_symbol":                     int(bool(raw_feats.get("has_at_symbol", 0))),
        "redirects_in_url":                  int(bool(raw_feats.get("redirects_in_url", 0))),
        "domain_has_numbers":                int(bool(raw_feats.get("domain_has_numbers", 0))),
        "domain_has_hyphens":                int(bool(raw_feats.get("domain_has_hyphens", 0))),
        # Header
        "header_score":                      round(hdr.get("score", 0), 6),
        "header_weight":                     round(hdr.get("weight", 0), 4),
        "header_flag_count":                 len(flags),
        "spf_result_raw":                    spf_raw,
        "dkim_result_raw":                   dkim_raw,
        "dmarc_result_raw":                  dmarc_raw,
        "spf_result":                        SPF_MAP.get(spf_raw, 0),
        "dkim_result":                       DKIM_MAP.get(dkim_raw, 0),
        "dmarc_result":                      DMARC_MAP.get(dmarc_raw, 0),
        "flag_spf_fail":                     int("spf_fail" in flags),
        "flag_dkim_fail":                    int("dkim_fail" in flags),
        "flag_dkim_missing":                 int("dkim_missing" in flags),
        "flag_dmarc_fail":                   int("dmarc_fail" in flags),
        "flag_reply_to_mismatch":            int("reply_to_mismatch" in flags),
        "flag_return_path_mismatch":         int("return_path_mismatch" in flags),
        "flag_bulk_mailer":                  int("bulk_mailer_detected" in flags),
        "flag_missing_message_id":           int("missing_message_id" in flags),
        "flag_missing_date":                 int("missing_date_header" in flags),
        "flag_excessive_hops":               int("excessive_routing_hops" in flags),
        # Threat intel
        "has_known_campaign":                int(ti.get("campaign_id", "Unknown") != "Unknown"),
        "actor_confidence":                  round(ti.get("actor_confidence", 0), 4),
        "related_domains_count":             len(ti.get("related_domains", [])),
        "ti_malicious_domain_count":         len(ti.get("malicious_domains", [])),
        "ti_feed_source_count":              len(ti.get("feed_sources", [])),
        "ti_global_reach_count":             len(ti.get("global_reach", [])),
        # IOC
        "ioc_risk_boost":                    round(ioc.get("risk_boost", 0), 4),
        "ioc_malicious_domain_count":        len(ioc.get("malicious_domains", [])),
        "ioc_malicious_ip_count":            len(ioc.get("malicious_ips", [])),
        "ioc_threat_family_count":           len(ioc.get("threat_families", [])),
        "ioc_source_count":                  len(ioc.get("sources", [])),
        # Dark web
        "dark_web_risk_raw":                 dw.get("dark_web_risk", "UNKNOWN"),
        "dark_web_risk":                     DARK_WEB_MAP.get(dw.get("dark_web_risk", "UNKNOWN"), 0),
        "dark_web_breach_count":             dw.get("breach_count", 0),
        "dark_web_total_exposed":            dw.get("total_exposed", 0),
        "dark_web_source_count":             len(dw.get("sources", [])),
        # Kill chain
        "kill_chain_active_stages":          kc.get("active_stage_count", 0),
        "kill_chain_overall_risk":           round(float(kc.get("overall_risk", 0)), 4) if kc.get("overall_risk") else 0,
        "kill_chain_attack_vector":          atk_vec,
        "kill_chain_attack_vector_encoded":  ATTACK_VEC_MAP.get(atk_vec,
                                                 3 if "Brand Impersonation" in atk_vec else -1),
        "kill_chain_is_brand_impersonation": int("Brand Impersonation" in atk_vec),
        "kill_chain_initial_access_risk":    stage_risks.get("Initial Access", 0),
        "kill_chain_credential_risk":        stage_risks.get("Credential Access", 0),
        "kill_chain_financial_risk":         stage_risks.get("Financial Impact", 0),
        "kill_chain_lateral_risk":           stage_risks.get("Lateral Movement", 0),
        "kill_chain_impact_level":           IMPACT_MAP.get(impact.get("level", "LOW"), 0),
        "kill_chain_impact_level_raw":       impact.get("level", "LOW"),
    }


def analyse_email(text: str) -> dict:
    """Call Sentinel API with retries and backoff."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(
                f"{API}/api/v1/analyze/email",
                json={"content": text, "options": {"run_visual": False, "run_threat_intel": True}},
                timeout=90,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response else 0
            # 402 = payment required (credit exhausted) — stop immediately
            if status == 402:
                log.error("CREDIT EXHAUSTED (402). Stopping.")
                raise SystemExit("OpenRouter credit exhausted.")
            log.warning(f"HTTP {status} on attempt {attempt}/{MAX_RETRIES} — retrying in {RETRY_DELAY}s")
        except Exception as e:
            log.warning(f"Error on attempt {attempt}/{MAX_RETRIES}: {e} — retrying in {RETRY_DELAY}s")
        time.sleep(RETRY_DELAY * attempt)
    return None  # all retries exhausted


def save_checkpoint(rows: list, path: str, is_append: bool):
    """Append rows to CSV (write header only on first write)."""
    df = pd.DataFrame(rows)
    if is_append and os.path.exists(path):
        df.to_csv(path, mode="a", header=False, index=False)
    else:
        df.to_csv(path, mode="w", header=True, index=False)
    log.info(f"  ✓ Checkpoint saved → {len(rows)} rows appended to {path}")


def get_resume_index(path: str) -> int:
    """Return number of rows already saved (to resume from there)."""
    if not os.path.exists(path):
        return 0
    try:
        existing = pd.read_csv(path)
        return len(existing)
    except Exception:
        return 0


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info(f"Dataset builder started — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    df = pd.read_csv(INPUT_CSV)
    total = len(df)
    resume_from = get_resume_index(OUTPUT_CSV)

    log.info(f"Total emails : {total}  (ham={len(df[df['label']==0])}, spam={len(df[df['label']==1])})")
    log.info(f"Already done : {resume_from}")
    log.info(f"Remaining    : {total - resume_from}")
    log.info(f"Checkpoint   : every {CHECKPOINT_EVERY} rows")
    log.info("=" * 60)

    if resume_from >= total:
        log.info("Dataset already complete. Nothing to do.")
        return

    df = df.iloc[resume_from:].reset_index(drop=True)

    buffer        = []
    errors        = 0
    processed     = 0
    first_write   = (resume_from == 0)

    for i, row in df.iterrows():
        label    = int(row["label"])
        text     = str(row["origin"])[:6000]
        abs_idx  = resume_from + i + 1
        tag      = "HAM " if label == 0 else "SPAM"

        result = analyse_email(text)

        if result is None:
            errors += 1
            log.warning(f"[{abs_idx}/{total}] {tag} — SKIPPED after {MAX_RETRIES} retries (errors={errors})")
            time.sleep(REQUEST_DELAY)
            continue

        try:
            features = extract_features(result, label)
            buffer.append(features)
            processed += 1

            if processed % 10 == 0 or processed == 1:
                log.info(f"[{abs_idx}/{total}] {tag} verdict={features['verdict']:<12} "
                         f"threat={features['threat_score']:.3f}  "
                         f"nlp={features['nlp_score']:.3f}  "
                         f"tactics={features['tactic_count']}  "
                         f"errors={errors}")

        except Exception as e:
            errors += 1
            log.warning(f"[{abs_idx}/{total}] {tag} — feature extraction failed: {e}")

        # Checkpoint
        if len(buffer) >= CHECKPOINT_EVERY:
            save_checkpoint(buffer, OUTPUT_CSV, is_append=not first_write)
            first_write = False
            buffer = []

        time.sleep(REQUEST_DELAY)

    # Save any remaining rows
    if buffer:
        save_checkpoint(buffer, OUTPUT_CSV, is_append=not first_write)

    final_count = get_resume_index(OUTPUT_CSV)
    log.info("=" * 60)
    log.info(f"DONE — {final_count} rows saved to {OUTPUT_CSV}")
    log.info(f"Errors/skipped: {errors}")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
