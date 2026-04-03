"""
BERT Phishing Detector — Fine-tuned on ISCX-2016 dataset.
Model: ealvaradob/bert-finetuned-phishing  (~96% accuracy on ISCX benchmark)

Features:
 - Lazy-loaded on first call (cached globally, ~2–5s warm-up once)
 - Async-safe via asyncio.to_thread()
 - Evaluation on held-out labeled email snippets at load time
 - Returns: phishing_prob (0–1), label, confidence, source
"""
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_MODEL_ID = "ealvaradob/bert-finetuned-phishing"

# ── Labeled evaluation set ───────────────────────────────────────────────────
# 40 email snippets with known labels for precision/recall/F1 reporting.
# Representative of real phishing and benign email patterns.
_EVAL_SAMPLES = [
    # ── Phishing ──────────────────────────────────────────────────────────────
    ("Your PayPal account has been limited. Click here to verify your identity within 24 hours or your account will be permanently closed.", 1),
    ("URGENT: Microsoft Security Alert — Your Office 365 account is at risk. Sign in immediately to prevent unauthorised access.", 1),
    ("Dear Customer, We have detected unusual activity on your Chase Online Banking account. Please verify your information now.", 1),
    ("Your Amazon account has been locked due to suspicious purchases. Click the link below to restore access and confirm your payment details.", 1),
    ("Congratulations! You have been selected for a $500 Apple gift card. Click here to claim your reward before it expires.", 1),
    ("IT Security Notice: Your password will expire in 1 hour. Update it immediately by logging in at the link provided.", 1),
    ("Dear Employee, The CEO has requested an urgent wire transfer of $47,000. Please initiate immediately and confirm. Keep this confidential.", 1),
    ("Your iCloud storage is full and your account will be suspended. Verify your billing information to continue service.", 1),
    ("IRS Tax Refund Notification: You are eligible for a $1,240 tax refund. Complete the form to receive your payment.", 1),
    ("IMPORTANT: Your Netflix account payment has failed. Update your credit card information to avoid service interruption.", 1),
    ("Verify your account now: Multiple failed login attempts detected on your Gmail account. Click to secure your account.", 1),
    ("HR Department: Direct deposit update required. Submit your new banking details by end of day to ensure timely payroll.", 1),
    ("Your Dropbox has been compromised. Login here to change your credentials and protect your files.", 1),
    ("FedEx Delivery Notice: Your package could not be delivered. Click to reschedule and pay the $3.99 customs fee.", 1),
    ("LinkedIn: Someone viewed your profile from Microsoft HR. Click to see their full details and accept the job offer.", 1),
    ("Your account has been flagged for suspicious activity. Confirm your identity by clicking this link within 2 hours.", 1),
    ("Dear Sir/Madam, I have $4.5M to transfer. I need your bank details. You will receive 30% commission. Please respond urgently.", 1),
    ("SECURITY ALERT: Your email will be deactivated in 24 hours unless you verify your account at the link below.", 1),
    ("Invoice #INV-29381 overdue. Click here to resolve your outstanding payment of $2,847 to avoid collections.", 1),
    ("Final Notice: Your DocuSign document has expired. Click to re-authenticate and access the pending legal agreement.", 1),
    # ── Benign ────────────────────────────────────────────────────────────────
    ("Hi team, please find attached the Q3 budget review slides. Let's discuss Thursday at 2pm. Best, Sarah", 0),
    ("Your order #112-3389204-9876543 has shipped and will arrive by Thursday. Track your package at amazon.com/orders.", 0),
    ("Meeting reminder: Product roadmap sync tomorrow at 10am PST. Zoom link in your calendar invite.", 0),
    ("Thank you for your payment of $89.99. Your Microsoft 365 subscription has been renewed through December 2026.", 0),
    ("GitHub Actions: Workflow 'CI/CD Pipeline' completed successfully on branch main. 142 tests passed.", 0),
    ("Your monthly statement for account ending 4421 is now available. Log in to bank.com to view it.", 0),
    ("Welcome to the team, Alex! Your onboarding schedule is attached. IT will be in touch about your equipment setup.", 0),
    ("Zoom Recording: The weekly all-hands meeting from Monday is now available. Link expires in 30 days.", 0),
    ("Your Jira ticket PROJ-2847 has been resolved by the engineering team. Please verify and close if satisfied.", 0),
    ("Newsletter: This month's cybersecurity digest — Top threats in Q1 2026, NIST framework updates, and more.", 0),
    ("Reminder: Employee performance review submissions are due by March 31st. Access the form on the HR portal.", 0),
    ("Your flight booking confirmation: AA2391 New York to San Francisco, March 28. E-ticket attached.", 0),
    ("Hi John, I reviewed your PR and left a few comments. Great work on the API refactor. -Mike", 0),
    ("Slack: You have 3 new messages in #engineering from Alice, Bob, and Carol about the deployment.", 0),
    ("DocuSign: The NDA you sent to Acme Corp has been signed. Download the completed document from your account.", 0),
    ("Your Cloudflare SSL certificate has been renewed automatically. No action needed.", 0),
    ("Calendar invite: Q2 planning session — April 5, 2026, 9:00–11:00 AM. Conference room B or Teams link.", 0),
    ("Invoice #8843 from Design Co. is attached for services in February 2026. Payment due March 30.", 0),
    ("Your AWS bill for March 2026 is $234.17. View itemized breakdown in your billing console.", 0),
    ("Thanks for completing the onboarding survey! Your feedback helps us improve the new employee experience.", 0),
]

# ── Global model state ────────────────────────────────────────────────────────
_pipeline = None
_eval_metrics: Optional[dict] = None
_load_attempted = False


def _load_model():
    """Load the BERT pipeline and run evaluation. Called once."""
    global _pipeline, _eval_metrics, _load_attempted
    _load_attempted = True
    try:
        from transformers import pipeline as hf_pipeline
        from sklearn.metrics import (
            accuracy_score, precision_score, recall_score,
            f1_score, roc_auc_score,
        )

        logger.info(f"[BERT] Loading {_MODEL_ID}...")
        clf = hf_pipeline(
            "text-classification",
            model=_MODEL_ID,
            truncation=True,
            max_length=512,
        )
        _pipeline = clf
        logger.info("[BERT] Model loaded successfully")

        # ── Evaluate on held-out samples ──────────────────────────────────────
        texts = [s[0] for s in _EVAL_SAMPLES]
        y_true = [s[1] for s in _EVAL_SAMPLES]

        outputs = clf(texts, batch_size=8)
        y_pred, y_prob = [], []
        for out in outputs:
            prob = out["score"] if out["label"] == "phishing" else 1.0 - out["score"]
            y_prob.append(prob)
            y_pred.append(1 if prob >= 0.5 else 0)

        _eval_metrics = {
            "accuracy":  round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1_score":  round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "roc_auc":   round(float(roc_auc_score(y_true, y_prob)), 4),
            "eval_set_size": len(_EVAL_SAMPLES),
            "model": _MODEL_ID,
            "architecture": "BERT-base-uncased (fine-tuned on ISCX-2016 phishing dataset)",
            "note": "Evaluated on 40 held-out email snippets — not seen during model training",
        }
        logger.info(
            f"[BERT] Evaluation: F1={_eval_metrics['f1_score']}, "
            f"AUC={_eval_metrics['roc_auc']}, "
            f"Acc={_eval_metrics['accuracy']}"
        )

    except ImportError as e:
        logger.warning(f"[BERT] transformers not available: {e}")
    except Exception as e:
        logger.warning(f"[BERT] Model load failed: {e}", exc_info=True)


def _get_pipeline():
    """Lazy-load the pipeline (once per process)."""
    global _load_attempted
    if _pipeline is None and not _load_attempted:
        _load_model()
    return _pipeline


def _predict_sync(text: str) -> dict:
    """Synchronous BERT prediction — call via asyncio.to_thread in async context."""
    clf = _get_pipeline()
    if clf is None:
        return {"phishing_prob": -1.0, "label": "unavailable", "confidence": 0.0, "source": "bert_unavailable"}

    text_truncated = text[:2000]  # BERT tokenizer handles further truncation
    try:
        out = clf(text_truncated)[0]
        label = out["label"]          # "phishing" or "benign"
        raw_score = float(out["score"])
        phishing_prob = raw_score if label == "phishing" else 1.0 - raw_score
        return {
            "phishing_prob": round(phishing_prob, 4),
            "label": label,
            "confidence": round(raw_score, 4),
            "source": "bert_finetuned_phishing",
        }
    except Exception as e:
        logger.warning(f"[BERT] Prediction failed: {e}")
        return {"phishing_prob": -1.0, "label": "error", "confidence": 0.0, "source": "bert_error"}


async def predict(text: str) -> dict:
    """Async BERT phishing prediction."""
    return await asyncio.to_thread(_predict_sync, text)


def get_evaluation_metrics() -> dict:
    """Return BERT model evaluation metrics."""
    if _eval_metrics:
        return _eval_metrics
    # If not loaded yet, load now (blocks but only once)
    if not _load_attempted:
        _load_model()
    return _eval_metrics or {"error": "BERT model not available", "model": _MODEL_ID}
