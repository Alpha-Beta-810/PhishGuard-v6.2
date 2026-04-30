# ================================================================
# train_model_v3.py — PhishGuard v3 Training Pipeline
# 32 features: URL structure + lexical + WHOIS stub + SSL stub
# ================================================================

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score, roc_auc_score, f1_score)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

from feature_extractor import extract_features, FEATURE_COLUMNS

RANDOM_STATE = 42
MAX_LEGIT    = 70_000

# ── Step 1: Load raw URL data ──────────────────────────────────
print("\n📂 Loading raw URL data...")

RAW_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'raw')

dfs = []
for fname, label in [
    ('phishing_phishtank.csv', 1),
    ('phishing_openphish.csv', 1),
    ('legitimate_tranco.csv', -1),
]:
    path = os.path.join(RAW_DIR, fname)
    if os.path.exists(path):
        df = pd.read_csv(path)
        if 'label' not in df.columns:
            df['label'] = label
        dfs.append(df[['url', 'label']])
        print(f"  ✅ {fname}: {len(df):,} rows")
    else:
        print(f"  ⚠️  {fname}: not found, skipping")

if not dfs:
    print("❌ No data files found. Copy your raw CSVs to data/raw/ first.")
    sys.exit(1)

all_data = pd.concat(dfs, ignore_index=True).dropna(subset=['url'])
print(f"\n  Total URLs: {len(all_data):,}")

# ── Step 2: Balance ───────────────────────────────────────────
phish = all_data[all_data['label'] == 1]
legit = all_data[all_data['label'] == -1]
print(f"  Phishing: {len(phish):,} | Legitimate: {len(legit):,}")

n_legit = min(len(legit), MAX_LEGIT, len(phish) * 2)
balanced = pd.concat([
    phish,
    legit.sample(n=n_legit, random_state=RANDOM_STATE)
]).sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)
print(f"  Balanced: {len(balanced):,} (phish={len(phish):,}, legit={n_legit:,})")

# ── Step 3: Extract features ──────────────────────────────────
print("\n⚙️  Extracting features (URL-only, no live WHOIS/SSL for training speed)...")

def safe_extract(url):
    try:
        return extract_features(str(url), include_whois=False, include_ssl=False)
    except Exception:
        return None

feature_rows = balanced['url'].apply(safe_extract)
valid_mask = feature_rows.notna()
feature_rows = feature_rows[valid_mask]
labels = balanced['label'][valid_mask]

feat_df = pd.DataFrame(feature_rows.tolist())
feat_df['label'] = labels.values

print(f"  ✅ Extracted {len(FEATURE_COLUMNS)} features from {len(feat_df):,} URLs")

X = feat_df[FEATURE_COLUMNS]
y = feat_df['label']

# ── Step 4: Train/test split ──────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
)
print(f"\n✂️  Train: {len(X_train):,} | Test: {len(X_test):,}")

# ── Step 5: Build stacking ensemble ───────────────────────────
print("\n🤖 Building stacking ensemble (RF + GBM + LR meta)...")

rf = RandomForestClassifier(
    n_estimators=200, max_depth=20, min_samples_leaf=2,
    class_weight='balanced', n_jobs=-1, random_state=RANDOM_STATE,
)

gbm = GradientBoostingClassifier(
    n_estimators=150, max_depth=6, learning_rate=0.1,
    subsample=0.8, random_state=RANDOM_STATE,
)

# Soft-voting ensemble
ensemble = VotingClassifier(
    estimators=[('rf', rf), ('gbm', gbm)],
    voting='soft',
    n_jobs=-1,
)

# Calibrate probabilities so the % score is trustworthy
print("  Calibrating probability outputs (isotonic)...")
model = CalibratedClassifierCV(ensemble, method='isotonic', cv=3)

model.fit(X_train, y_train)
print("  ✅ Training complete!")

# ── Step 6: Evaluate ─────────────────────────────────────────
print("\n📈 Evaluating on held-out test set...")
y_pred  = model.predict(X_test)
y_proba = model.predict_proba(X_test)

classes = list(model.classes_)
phish_idx = classes.index(1) if 1 in classes else 1
phish_proba = y_proba[:, phish_idx]

accuracy = accuracy_score(y_test, y_pred)
roc_auc  = roc_auc_score(y_test, phish_proba)
f1       = f1_score(y_test, y_pred, pos_label=1)

print(f"\n  🎯 Accuracy  : {accuracy:.4f}")
print(f"  📐 ROC-AUC   : {roc_auc:.4f}")
print(f"  🏅 F1 (phish): {f1:.4f}")

print("\n  📊 Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()
print(f"  🧾 Confusion Matrix:")
print(f"     TP={tp:,}  FP={fp:,}")
print(f"     FN={fn:,}  TN={tn:,}")
print(f"\n  ⚠️  False Negative Rate (missed phishing): {fn/(fn+tp):.2%}")
print(f"  ⚠️  False Positive Rate (legit flagged):   {fp/(fp+tn):.2%}")

# ── Step 7: Cross-validation check ───────────────────────────
print("\n🔁 Running 5-fold cross-validation on training data...")
cv_scores = cross_val_score(
    VotingClassifier(estimators=[('rf', rf), ('gbm', gbm)], voting='soft'),
    X_train, y_train, cv=5, scoring='roc_auc', n_jobs=-1
)
print(f"  CV ROC-AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# ── Step 8: Feature importances ───────────────────────────────
print("\n🔍 Top 15 Feature Importances (from RF inside ensemble):")
try:
    # Navigate through CalibratedClassifierCV → VotingClassifier → RF
    base_ensemble = model.calibrated_classifiers_[0].estimator
    rf_est = dict(base_ensemble.estimators).get('rf', None)
    if rf_est:
        imp = pd.Series(rf_est.feature_importances_, index=FEATURE_COLUMNS)
        print(imp.sort_values(ascending=False).head(15).to_string())
except Exception as e:
    print(f"  (Could not extract importances: {e})")

# ── Step 9: Save ─────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'model', 'phishing_model_v3.pkl')
joblib.dump((model, FEATURE_COLUMNS), MODEL_PATH)
print(f"\n💾 Model saved → {MODEL_PATH}")
print(f"   Features ({len(FEATURE_COLUMNS)}): {FEATURE_COLUMNS}")
print("\n✅ Done! Start the backend with: python src/backend.py")
