#!/usr/bin/env python3
"""
WEBSHELL DETECTOR - ENHANCED TRAINING v8.0

Key improvements:
1. Support for new ASPX features
2. Better feature boosting strategy
3. Improved threshold calculation
4. Validation on clean samples
5. Framework-aware training
"""

import os
import sys
import json
import math
import time
import argparse
import traceback
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed, ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

import numpy as np
import pandas as pd

import joblib
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    roc_curve,
)
from sklearn.preprocessing import RobustScaler

from imblearn.over_sampling import BorderlineSMOTE

try:
    import lightgbm as lgb
except Exception:
    lgb = None

from extractor import WebshellFeatureExtractor


def _extract_batch_worker(filepaths: List[str]) -> List[Tuple[str, Dict[str, float]]]:
    extractor = WebshellFeatureExtractor()
    results = []
    for fp in filepaths:
        code = extractor.safe_read(fp)
        if not code:
            continue
        feats = extractor.extract_features_from_code(code, fp)
        if feats:
            results.append((fp, feats))
    return results


@dataclass
class TrainConfig:
    clean_dirs: List[str]
    webshell_dirs: List[str]
    out_dir: str = "models"
    workers: int = 4
    batch_size: int = 150
    use_threading: bool = False
    random_state: int = 42


class WebshellTrainer:
    def __init__(self, cfg: TrainConfig):
        self.cfg = cfg
        self.extractor = WebshellFeatureExtractor()
        self.workers = cfg.workers
        self.batch_size = cfg.batch_size
        self.use_threading = cfg.use_threading
        self.random_state = cfg.random_state

        os.makedirs(cfg.out_dir, exist_ok=True)

    def _collect_files(self, directory: str, recursive: bool = True) -> List[str]:
        exts = {".php", ".asp", ".aspx", ".jsp", ".jspx", ".py", ".js", ".txt", 
                ".cs", ".config", ".inc", ".phtml", ".cgi", ".pl", ".ascx", 
                ".asax", ".ashx", ".asmx"}
        files = []
        directory = str(directory)
        if recursive:
            for root, _, names in os.walk(directory):
                for n in names:
                    p = os.path.join(root, n)
                    if os.path.splitext(p)[1].lower() in exts:
                        files.append(p)
        else:
            for n in os.listdir(directory):
                p = os.path.join(directory, n)
                if os.path.isfile(p) and os.path.splitext(p)[1].lower() in exts:
                    files.append(p)
        return files

    def _process_futures(self, futures, files, label, rows, labels, paths):
        done = 0
        total = len(files)
        processed_files = 0
        skipped_batches = 0
        
        for fut in as_completed(futures):
            try:
                batch_res = fut.result()
                for fp, feats in batch_res:
                    feats = dict(feats)
                    feats.pop("_version", None)
                    feats.pop("_group_id", None)
                    # Remove string features that can't be used in training
                    feats.pop("detected_framework", None)
                    rows.append(feats)
                    labels.append(label)
                    paths.append(fp)
                    processed_files += 1
            except Exception as e:
                skipped_batches += 1
                if skipped_batches <= 3:
                    print(f"  ⚠️  Batch error: {type(e).__name__}: {str(e)[:100]}")
            
            done += 1
            if done % 10 == 0 or done == len(futures):
                print(f"  {label}: {processed_files}/{total} files extracted (batches: {done}/{len(futures)}, errors: {skipped_batches})...")
        
        if skipped_batches > 0:
            print(f"  ⚠️  Total batches with errors: {skipped_batches}/{len(futures)}")

    def _boost_behavioral_features(self, X, feature_names=None):
        """
        AGGRESSIVE boosting for behavioral patterns
        Increase factors to make signatures more important than stats
        """
        if feature_names is None:
            feature_names = self.feature_names
        
        # CRITICAL patterns (3.5x - INCREASED from 1.8x)
        critical_keys = {
            "behavior_input_decode_exec",
            "behavior_password_backdoor",
            "behavior_upload_chmod",
            "has_assign_input_then_call",
            "behavior_aspx_process_shell",
            "behavior_aspx_privilege_pipe",
            "behavior_aspx_file_manager",
            "behavior_jsp_memory_shell",
            "behavior_jsp_request_exec",
            "behavior_jsp_hardcoded_backdoor",  # ← THÊM
            "behavior_jscript_webshell",
            "behavior_dotnet_memory_shell",
        }
        
        # STRONG patterns (2.5x - INCREASED from 1.4x)
        strong_keys = {
            "behavior_cookie_hash_gate_dyn_call",
            "behavior_aspx_tunneling",
            "behavior_jsp_http_tunneling",
            "behavior_jsp_http_backdoor",  # ← THÊM
            "has_superglobal_var_call",
            "behavior_filterinput_exec",
            "behavior_arbitrary_upload_path",
            "behavior_cookie_exec",
            "behavior_rawbody_backdoor",
            "behavior_file_manager",  # ← ĐÃ THÊM Ở FIX TRƯỚC
        }
        
        # Intent/threat scores (2.0x - NEW)
        intent_keys = [
            "intent_webshell_score",
            "intent_backdoor_score",
            "intent_c2_score",
            "intent_privilege_escalation",
            "overall_threat_score",
        ]
        
        critical_indices = [i for i, name in enumerate(feature_names) if name in critical_keys]
        strong_indices = [i for i, name in enumerate(feature_names) if name in strong_keys]
        intent_indices = [i for i, name in enumerate(feature_names) if name in intent_keys]

        critical_factor = 3.5  # INCREASED
        strong_factor = 2.5    # INCREASED
        intent_factor = 2.0    # NEW

        X_boosted = X.copy()
        if critical_indices:
            X_boosted[:, critical_indices] *= critical_factor
        if strong_indices:
            X_boosted[:, strong_indices] *= strong_factor
        if intent_indices:
            X_boosted[:, intent_indices] *= intent_factor

        print(f"\n🚀 Boosted {len(critical_indices)} critical features by {critical_factor}x")
        print(f"🚀 Boosted {len(strong_indices)} strong features by {strong_factor}x")
        print(f"🚀 Boosted {len(intent_indices)} intent features by {intent_factor}x")
        
        return X_boosted
    def load_dataset(self) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
        rows = []
        labels = []
        paths = []

        for directory in self.cfg.clean_dirs:
            files = self._collect_files(directory, recursive=True)
            if len(files) == 0:
                print(f"âš ï¸  No files found in {directory}")
                continue

            print(f"\nðŸ“‚ Processing {len(files)} files from {directory}...")

            batches = [files[i:i + self.batch_size] for i in range(0, len(files), self.batch_size)]

            if self.use_threading:
                with ThreadPoolExecutor(max_workers=self.workers) as executor:
                    futures = [executor.submit(_extract_batch_worker, batch) for batch in batches]
                    self._process_futures(futures, files, "Clean", rows, labels, paths)
            else:
                with ProcessPoolExecutor(max_workers=self.workers) as executor:
                    futures = [executor.submit(_extract_batch_worker, batch) for batch in batches]
                    self._process_futures(futures, files, "Clean", rows, labels, paths)

        for directory in self.cfg.webshell_dirs:
            files = self._collect_files(directory, recursive=True)
            if len(files) == 0:
                print(f"âš ï¸  No files found in {directory}")
                continue

            print(f"\nðŸ“‚ Processing {len(files)} files from {directory}...")

            batches = [files[i:i + self.batch_size] for i in range(0, len(files), self.batch_size)]

            if self.use_threading:
                with ThreadPoolExecutor(max_workers=self.workers) as executor:
                    futures = [executor.submit(_extract_batch_worker, batch) for batch in batches]
                    self._process_futures(futures, files, "Webshell", rows, labels, paths)
            else:
                with ProcessPoolExecutor(max_workers=self.workers) as executor:
                    futures = [executor.submit(_extract_batch_worker, batch) for batch in batches]
                    self._process_futures(futures, files, "Webshell", rows, labels, paths)

        if not rows:
            raise RuntimeError("No features extracted. Check your dataset directories and file types.")

        df = pd.DataFrame(rows).fillna(0.0)
        y = np.array([1 if l == "Webshell" else 0 for l in labels], dtype=np.int32)

        feature_names = list(df.columns)

        print("\nðŸ“Š Dataset Summary:")
        print(f"   Total samples: {len(df)}")
        print(f"   Features: {len(feature_names)}")
        print(f"   Clean: {np.sum(y==0)}")
        print(f"   Webshell: {np.sum(y==1)}")
        
        # Feature analysis
        print("\nðŸ” Feature Analysis:")
        aspx_features = [f for f in feature_names if 'aspx' in f.lower()]
        behavior_features = [f for f in feature_names if 'behavior_' in f]
        intent_features = [f for f in feature_names if 'intent_' in f]
        
        print(f"   ASPX features: {len(aspx_features)}")
        print(f"   Behavior features: {len(behavior_features)}")
        print(f"   Intent features: {len(intent_features)}")

        return df, y, paths

    def train(self):
        if lgb is None:
            raise RuntimeError("lightgbm is not installed. Please install lightgbm.")

        X_df, y, paths = self.load_dataset()
        feature_names = list(X_df.columns)

        # Train/val split
        X_train, X_val, y_train, y_val = train_test_split(
            X_df.values, y, test_size=0.2, random_state=self.random_state, stratify=y
        )

        print(f"\nðŸ“Š Split Summary:")
        print(f"   Train: {len(X_train)} samples ({np.sum(y_train==1)} webshells)")
        print(f"   Val:   {len(X_val)} samples ({np.sum(y_val==1)} webshells)")

        # SMOTE
        print("\nðŸ§ª Applying BorderlineSMOTE...")
        smote = BorderlineSMOTE(random_state=self.random_state)
        X_train_sm, y_train_sm = smote.fit_resample(X_train, y_train)

        print(f"   After SMOTE: {X_train_sm.shape[0]} samples")
        print(f"   Clean: {np.sum(y_train_sm==0)}, Webshell: {np.sum(y_train_sm==1)}")
        print("\n⚖️  Calculating sample weights...")

        # Get feature indices
        feature_dict = {name: i for i, name in enumerate(feature_names)}

        critical_features = [
            "behavior_input_decode_exec",
            "behavior_password_backdoor",
            "behavior_jscript_webshell",
            "behavior_dotnet_memory_shell",
            "behavior_aspx_process_shell",
            "behavior_jsp_memory_shell",
            "behavior_jsp_hardcoded_backdoor",  # ← THÊM
        ]

        # Calculate weights
        sample_weights = np.ones(len(X_train_sm), dtype=np.float32)
        for i, x in enumerate(X_train_sm):
            # If sample is webshell (y=1) AND has critical signatures
            if y_train_sm[i] == 1:
                has_critical = any(
                    x[feature_dict.get(f, -1)] > 0 
                    for f in critical_features 
                    if feature_dict.get(f, -1) >= 0
                )
                
                # ← THÊM ĐOẠN NÀY
                # File manager + password gate = critical webshell
                has_file_manager_auth = False
                if (feature_dict.get("behavior_file_manager", -1) >= 0 and 
                    feature_dict.get("behavior_password_backdoor", -1) >= 0):
                    has_file_manager_auth = (
                        x[feature_dict.get("behavior_file_manager", -1)] > 0 and
                        x[feature_dict.get("behavior_password_backdoor", -1)] > 0
                    )
                # ← KẾT THÚC ĐOẠN THÊM
                
                if has_critical or has_file_manager_auth:  # ← SỬA DÒNG NÀY
                    sample_weights[i] = 3.0
                else:
                    sample_weights[i] = 1.5
            else:
                sample_weights[i] = 1.0

        print(f"   Weighted samples: {np.sum(sample_weights > 1.0)} / {len(sample_weights)}")
        print(f"   High weight (3.0x): {np.sum(sample_weights == 3.0)}")
        print(f"   Medium weight (1.5x): {np.sum(sample_weights == 1.5)}")
        # Boost behavioral features
        X_train_sm = self._boost_behavioral_features(X_train_sm, feature_names)
        X_val_boost = self._boost_behavioral_features(X_val, feature_names)

        # Robust scaling
        print("\nðŸ“ Scaling features...")
        scaler = RobustScaler()
        X_train_scaled = scaler.fit_transform(X_train_sm)
        X_val_scaled = scaler.transform(X_val_boost)

        print("\nðŸŽ¯ Training LightGBM model...")

        model = lgb.LGBMClassifier(
            n_estimators=800,
            learning_rate=0.03,
            num_leaves=64,
            max_depth=-1,
            subsample=0.85,
            colsample_bytree=0.85,
            min_child_samples=20,
            reg_alpha=0.2,
            reg_lambda=0.2,
            
            # NEW PARAMETERS - Focus on rare features
            min_data_in_leaf=10,           # Reduced from default 20
            min_sum_hessian_in_leaf=0.001, # Allow rare patterns
            feature_fraction=0.9,           # Sample more features per tree
            bagging_fraction=0.9,
            bagging_freq=5,
            
            # Force model to use signature features
            max_bin=255,                    # More bins for categorical features
            
            random_state=self.random_state,
            n_jobs=-1,
            verbose=-1
        )

        model.fit(
            X_train_scaled, y_train_sm,
            eval_set=[(X_val_scaled, y_val)],
            eval_metric="auc",
            sample_weight=sample_weights
        )

        # Validation metrics
        val_probs = model.predict_proba(X_val_scaled)[:, 1]
        auc = roc_auc_score(y_val, val_probs)

        print(f"\nâœ… Validation AUC: {auc:.4f}")

        # Calculate thresholds
        precision, recall, thresholds = precision_recall_curve(y_val, val_probs)

        # Blocking: precision >= 0.99
        blocking_threshold = 0.9
        best_r = -1
        for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
            if p >= 0.99 and r > best_r:
                best_r = r
                blocking_threshold = float(t)

        # Hunting: recall >= 0.96
        hunting_threshold = 0.5
        best_p = -1
        for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
            if r >= 0.96 and p > best_p:
                best_p = p
                hunting_threshold = float(t)

        # Validate thresholds on clean samples
        val_clean_probs = val_probs[y_val == 0]
        val_webshell_probs = val_probs[y_val == 1]
        
        fp_rate_hunting = np.mean(val_clean_probs >= hunting_threshold)
        fp_rate_blocking = np.mean(val_clean_probs >= blocking_threshold)
        
        fn_rate_hunting = np.mean(val_webshell_probs < hunting_threshold)
        fn_rate_blocking = np.mean(val_webshell_probs < blocking_threshold)

        print("\nðŸŽšï¸ Thresholds:")
        print(f"   Blocking: {blocking_threshold:.4f}")
        print(f"     - Precision: â‰¥0.99")
        print(f"     - FP rate: {fp_rate_blocking*100:.2f}%")
        print(f"     - FN rate: {fn_rate_blocking*100:.2f}%")
        print(f"\n   Hunting:  {hunting_threshold:.4f}")
        print(f"     - Recall: â‰¥0.96")
        print(f"     - FP rate: {fp_rate_hunting*100:.2f}%")
        print(f"     - FN rate: {fn_rate_hunting*100:.2f}%")

        # Adjust if FP rate too high
        if fp_rate_hunting > 0.10:
            print(f"\nâš ï¸  WARNING: Hunting FP rate too high ({fp_rate_hunting*100:.2f}%), adjusting...")
            for t in np.linspace(hunting_threshold, blocking_threshold, 100):
                fp = np.mean(val_clean_probs >= t)
                fn = np.mean(val_webshell_probs < t)
                if fp <= 0.08:
                    hunting_threshold = float(t)
                    print(f"   Adjusted: {hunting_threshold:.4f} (FP: {fp*100:.2f}%, FN: {fn*100:.2f}%)")
                    break

        # Feature importance analysis
        print("\nðŸ” Top 20 Most Important Features:")
        feature_importance = model.feature_importances_
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': feature_importance
        }).sort_values('importance', ascending=False)
        
        for idx, row in importance_df.head(20).iterrows():
            print(f"   {row['feature']:40s} {row['importance']:.4f}")

        # Save artifacts
        out_dir = self.cfg.out_dir
        model_path = os.path.join(out_dir, "webshell_model.joblib")
        scaler_path = os.path.join(out_dir, "webshell_scaler.joblib")
        meta_path = os.path.join(out_dir, "webshell_meta.json")
        importance_path = os.path.join(out_dir, "feature_importance.csv")

        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
        importance_df.to_csv(importance_path, index=False)

        meta = {
            "feature_names": feature_names,
            "blocking_threshold": blocking_threshold,
            "hunting_threshold": hunting_threshold,
            "extractor_version": self.extractor.VERSION,
            "fp_rate_hunting": float(fp_rate_hunting),
            "fp_rate_blocking": float(fp_rate_blocking),
            "fn_rate_hunting": float(fn_rate_hunting),
            "fn_rate_blocking": float(fn_rate_blocking),
            "validation_auc": float(auc),
            "train_samples": int(len(X_train_sm)),
            "val_samples": int(len(X_val)),
            "aspx_features": len([f for f in feature_names if 'aspx' in f.lower()]),
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        print("\nðŸ’¾ Saved:")
        print("  ", model_path)
        print("  ", scaler_path)
        print("  ", meta_path)
        print("  ", importance_path)
        
        print("\nðŸŽ‰ Training complete!")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--clean-dir", default="dataset/clean", 
                       help="Directory of clean samples (comma-separated)")
    parser.add_argument("--webshell-dir", default="dataset/webshell", 
                       help="Directory of webshell samples (comma-separated)")
    parser.add_argument("--out-dir", default="models", help="Output directory")
    parser.add_argument("--workers", type=int, default=4, help="Number of workers")
    parser.add_argument("--batch-size", type=int, default=150, help="Batch size for processing")
    parser.add_argument("--threading", action="store_true", help="Use threading instead of multiprocessing")
    args = parser.parse_args()

    clean_dirs = [x.strip() for x in args.clean_dir.split(",") if x.strip()]
    webshell_dirs = [x.strip() for x in args.webshell_dir.split(",") if x.strip()]

    cfg = TrainConfig(
        clean_dirs=clean_dirs,
        webshell_dirs=webshell_dirs,
        out_dir=args.out_dir,
        workers=args.workers,
        batch_size=args.batch_size,
        use_threading=args.threading,
    )

    print("=" * 80)
    print("WEBSHELL DETECTOR TRAINING v8.0")
    print("=" * 80)
    print(f"\nðŸ“ Clean directories: {clean_dirs}")
    print(f"ðŸ“ Webshell directories: {webshell_dirs}")
    print(f"ðŸ“ Output directory: {args.out_dir}")
    print(f"âš™ï¸  Workers: {args.workers}")
    print(f"âš™ï¸  Batch size: {args.batch_size}")
    print(f"âš™ï¸  Mode: {'Threading' if args.threading else 'Multiprocessing'}")

    trainer = WebshellTrainer(cfg)
    trainer.train()


if __name__ == "__main__":
    main()