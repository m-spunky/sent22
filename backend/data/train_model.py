"""
Train XGBoost fusion classifier on sentinel_dataset.csv
Split: 70% train / 15% val / 15% test
"""
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report, confusion_matrix
)
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

DATASET  = "/root/sent/sentinel/backend/data/sentinel_dataset.csv"
MODEL_OUT = "/root/sent/sentinel/backend/models/fusion_xgb.pkl"
META_OUT  = "/root/sent/sentinel/backend/models/fusion_xgb_meta.json"

# Drop columns not suitable as ML features
DROP_COLS = [
    "verdict",               # target leakage (string form)
    "recommended_action",    # target leakage (string form)
    "input_type",            # always "email"
    "nlp_source",            # string, already encoded
    "spf_result_raw",        # string, already encoded
    "dkim_result_raw",       # string, already encoded
    "dmarc_result_raw",      # string, already encoded
    "dark_web_risk_raw",     # string, already encoded
    "kill_chain_attack_vector",       # string, already encoded
    "kill_chain_impact_level_raw",    # string, already encoded
]

# ── Load ─────────────────────────────────────────────────────────────────────
df = pd.read_csv(DATASET)
print(f"Dataset: {df.shape[0]} rows × {df.shape[1]} cols")
print(f"Label distribution: {df['label'].value_counts().to_dict()}")

df = df.drop(columns=[c for c in DROP_COLS if c in df.columns])

X = df.drop(columns=["label"])
y = df["label"]

print(f"\nFeatures used: {X.shape[1]}")

# ── Split 70 / 15 / 15 ───────────────────────────────────────────────────────
X_train, X_tmp, y_train, y_tmp = train_test_split(
    X, y, test_size=0.30, random_state=42, stratify=y
)
X_val, X_test, y_val, y_test = train_test_split(
    X_tmp, y_tmp, test_size=0.50, random_state=42, stratify=y_tmp
)

print(f"\nSplit:")
print(f"  Train : {len(X_train):>5}  (spam={y_train.sum()}, ham={len(y_train)-y_train.sum()})")
print(f"  Val   : {len(X_val):>5}  (spam={y_val.sum()}, ham={len(y_val)-y_val.sum()})")
print(f"  Test  : {len(X_test):>5}  (spam={y_test.sum()}, ham={len(y_test)-y_test.sum()})")

# ── Class weight (handle imbalance 5182 spam vs 1518 ham) ────────────────────
scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()
print(f"\nClass imbalance ratio (scale_pos_weight): {scale_pos_weight:.3f}")

# ── Train ─────────────────────────────────────────────────────────────────────
print("\nTraining XGBoost...")
model = xgb.XGBClassifier(
    n_estimators=400,
    max_depth=6,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    scale_pos_weight=scale_pos_weight,
    use_label_encoder=False,
    eval_metric="logloss",
    early_stopping_rounds=20,
    random_state=42,
    n_jobs=-1,
)

model.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=50,
)

# ── Evaluate ──────────────────────────────────────────────────────────────────
def evaluate(name, X, y):
    preds  = model.predict(X)
    probas = model.predict_proba(X)[:, 1]
    acc    = accuracy_score(y, preds)
    prec   = precision_score(y, preds, zero_division=0)
    rec    = recall_score(y, preds, zero_division=0)
    f1     = f1_score(y, preds, zero_division=0)
    auc    = roc_auc_score(y, probas)
    print(f"\n── {name} ──")
    print(f"  Accuracy : {acc:.4f}")
    print(f"  Precision: {prec:.4f}")
    print(f"  Recall   : {rec:.4f}")
    print(f"  F1       : {f1:.4f}")
    print(f"  AUC-ROC  : {auc:.4f}")
    print(f"\n  Confusion matrix (rows=actual, cols=predicted):")
    cm = confusion_matrix(y, preds)
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}")
    print(f"\n  Classification report:")
    print(classification_report(y, preds, target_names=["ham","spam"], digits=4))
    return {"accuracy": round(acc,4), "precision": round(prec,4),
            "recall": round(rec,4), "f1_score": round(f1,4), "roc_auc": round(auc,4)}

train_metrics = evaluate("TRAIN", X_train, y_train)
val_metrics   = evaluate("VALIDATION", X_val, y_val)
test_metrics  = evaluate("TEST", X_test, y_test)

# ── Top features ──────────────────────────────────────────────────────────────
importances = pd.Series(model.feature_importances_, index=X.columns)
top20 = importances.nlargest(20)
print("\n── Top 20 feature importances ──")
for feat, score in top20.items():
    print(f"  {feat:<45} {score:.4f}")

# ── Save model ────────────────────────────────────────────────────────────────
with open(MODEL_OUT, "wb") as f:
    pickle.dump(model, f)

meta = {
    "model":        "XGBClassifier",
    "features":     list(X.columns),
    "n_features":   X.shape[1],
    "train_size":   len(X_train),
    "val_size":     len(X_val),
    "test_size":    len(X_test),
    "train_metrics": train_metrics,
    "val_metrics":   val_metrics,
    "test_metrics":  test_metrics,
    "top_features":  top20.index.tolist(),
}
with open(META_OUT, "w") as f:
    json.dump(meta, f, indent=2)

print(f"\nModel saved → {MODEL_OUT}")
print(f"Meta  saved → {META_OUT}")
