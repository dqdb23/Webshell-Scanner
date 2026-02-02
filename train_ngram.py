#!/usr/bin/env python3
"""
N-GRAM WEBSHELL DETECTOR TRAINING - TRULY OPTIMIZED v2.1

Key improvements:
1. TRUE HYBRID: char n-grams (obfuscation) + word n-grams (semantic patterns)
2. char analyzer (not char_wb) to catch punctuation like <?php, $_, ::
3. Smarter base64 handling: preserve length signal
4. Removed SelectKBest (ElasticNet does feature selection)
5. Cleaned up unused imports
"""

import os
import sys
import json
import argparse
import re
from pathlib import Path
from typing import List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import (
    classification_report, 
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
)
from sklearn.pipeline import FeatureUnion


class TrulyOptimizedNgramTrainer:
    def __init__(self, output_dir="models", use_gridsearch=False):
        self.output_dir = output_dir
        self.use_gridsearch = use_gridsearch
        os.makedirs(output_dir, exist_ok=True)
        
        # TRUE HYBRID: char + word n-grams
        char_vectorizer = TfidfVectorizer(
            analyzer='char',          # NOT char_wb - catches <?php, $_, ::, etc.
            ngram_range=(3, 6),       # 3-6 char sequences (extended range)
            max_features=15000,       # More features for char-level
            min_df=2,
            max_df=0.90,
            sublinear_tf=True,
            strip_accents='unicode',
            lowercase=True,
            use_idf=True,
            smooth_idf=True,
            norm='l2',
        )
        
        word_vectorizer = TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 3),       # 1-3 word sequences
            max_features=8000,
            min_df=3,
            max_df=0.85,
            sublinear_tf=True,
            strip_accents='unicode',
            lowercase=True,
            token_pattern=r'\b\w+\b',
            use_idf=True,
            smooth_idf=True,
            norm='l2',
        )
        
        # Combine both with FeatureUnion
        self.vectorizer = FeatureUnion([
            ('char', char_vectorizer),
            ('word', word_vectorizer),
        ])
        
        # ElasticNet does feature selection internally - no need for SelectKBest
        self.model = LogisticRegression(
            C=0.5,
            max_iter=2000,
            class_weight='balanced',
            solver='saga',
            penalty='elasticnet',
            l1_ratio=0.3,             # 30% L1 (sparsity), 70% L2 (smoothness)
            random_state=42,
            n_jobs=-1,
            verbose=0
        )
    
    def _preprocess_code(self, code: str) -> str:
        """Aggressive preprocessing with smart base64 handling"""
        if not code:
            return ""
        
        # Remove null bytes
        code = code.replace('\x00', '')
        
        # Remove HTML/XML comments
        code = re.sub(r'<!--[\s\S]*?-->', ' ', code)
        code = re.sub(r'<%--[\s\S]*?--%>', ' ', code)
        
        # Remove C-style comments
        code = re.sub(r'/\*[\s\S]*?\*/', ' ', code)
        code = re.sub(r'//.*?$', ' ', code, flags=re.MULTILINE)
        
        # SMART base64 handling: preserve length signal
        def base64_replacer(match):
            length = len(match.group(0))
            if length < 200:
                return match.group(0)  # Keep short ones
            elif length < 500:
                return ' BASE64_LEN_200_500 '
            elif length < 2000:
                return ' BASE64_LEN_500_2K '
            else:
                return ' BASE64_LEN_GT2K '  # Very suspicious!
        
        code = re.sub(r'[A-Za-z0-9+/]{200,}={0,2}', base64_replacer, code)
        
        # Normalize excessive whitespace (but don't collapse completely)
        code = re.sub(r'\s+', ' ', code)
        code = code.strip()
        
        # Truncate (larger limit for complex files)
        if len(code) > 100000:
            code = code[:100000]
        
        return code
    
    def _load_file(self, filepath: str, max_size_kb: int = 1500) -> Tuple[str, str]:
        """Load single file with aggressive retry"""
        try:
            size_kb = os.path.getsize(filepath) / 1024
            if size_kb > max_size_kb:
                return None
            
            with open(filepath, 'rb') as f:
                raw = f.read()
            
            if len(raw) == 0:
                return None
            
            # Try common encodings
            encodings = [
                'utf-8', 'utf-16', 'utf-16-le', 'utf-16-be',
                'latin-1', 'cp1252', 'iso-8859-1',
                'gb2312', 'gbk', 'big5',
                'ascii'
            ]
            
            code = None
            for encoding in encodings:
                try:
                    code = raw.decode(encoding, errors='strict')
                    if len(code) >= 20:
                        break
                except (UnicodeDecodeError, UnicodeError):
                    continue
            
            # Last resort
            if code is None or len(code) < 20:
                code = raw.decode('utf-8', errors='replace')
                if len(code) < 20:
                    return None
            
            return (filepath, code)
            
        except Exception:
            return None
    
    def load_files(self, directory: str, label: str, max_workers: int = 4) -> List[Tuple[str, str]]:
        """Parallel file loading"""
        exts = {'.php', '.asp', '.aspx', '.jsp', '.jspx', '.py', '.js', 
                '.cs', '.txt', '.inc', '.phtml', '.ascx', '.asax', '.ashx', '.asmx'}
        
        filepaths = []
        for root, _, files in os.walk(directory):
            for filename in files:
                if os.path.splitext(filename)[1].lower() in exts:
                    filepaths.append(os.path.join(root, filename))
        
        print(f"\n📂 Loading {label} files from: {directory}")
        print(f"   Found {len(filepaths)} candidate files")
        
        samples = []
        skip_total = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._load_file, fp): fp for fp in filepaths}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 500 == 0:
                    print(f"   Progress: {completed}/{len(filepaths)}")
                
                result = future.result()
                if result:
                    samples.append(result)
                else:
                    skip_total += 1
        
        print(f"   ✅ Loaded {len(samples)} {label} samples")
        if skip_total > 0:
            print(f"   ⚠️  Skipped {skip_total} files")
        
        return samples
    
    def train(self, clean_dir: str, webshell_dir: str):
        """Train with proper validation"""
        print("="*80)
        print("N-GRAM WEBSHELL DETECTOR - TRULY OPTIMIZED v2.1")
        print("="*80)
        
        # Load data
        clean_samples = self.load_files(clean_dir, "clean", max_workers=4)
        webshell_samples = self.load_files(webshell_dir, "webshell", max_workers=4)
        
        if len(clean_samples) < 100 or len(webshell_samples) < 100:
            raise ValueError("Not enough samples!")
        
        # Preprocess
        print("\n🔄 Preprocessing code...")
        
        clean_codes = [self._preprocess_code(code) for _, code in clean_samples]
        webshell_codes = [self._preprocess_code(code) for _, code in webshell_samples]
        
        print(f"   ✅ Preprocessed {len(clean_codes)} clean samples")
        print(f"   ✅ Preprocessed {len(webshell_codes)} webshell samples")
        
        # Combine
        X_all = clean_codes + webshell_codes
        y_all = np.array([0] * len(clean_codes) + [1] * len(webshell_codes))
        
        print(f"\n📊 Dataset Summary:")
        print(f"   Clean:    {len(clean_codes)}")
        print(f"   Webshell: {len(webshell_codes)}")
        print(f"   Total:    {len(X_all)}")
        print(f"   Balance:  {len(webshell_codes)/len(clean_codes):.2f}")
        
        # Train/test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_all, y_all, 
            test_size=0.15,
            random_state=42, 
            stratify=y_all
        )
        
        # Further split train into train/val
        X_train, X_val, y_train, y_val = train_test_split(
            X_train, y_train,
            test_size=0.15,
            random_state=42,
            stratify=y_train
        )
        
        print(f"\n✂️  Split:")
        print(f"   Train: {len(X_train)} ({np.sum(y_train==1)} webshells)")
        print(f"   Val:   {len(X_val)} ({np.sum(y_val==1)} webshells)")
        print(f"   Test:  {len(X_test)} ({np.sum(y_test==1)} webshells)")
        
        # Vectorize with HYBRID char + word
        print("\n🔤 Extracting HYBRID features (char + word n-grams)...")
        X_train_vec = self.vectorizer.fit_transform(X_train)
        X_val_vec = self.vectorizer.transform(X_val)
        X_test_vec = self.vectorizer.transform(X_test)
        
        print(f"   Feature matrix: {X_train_vec.shape}")
        print(f"   Sparsity: {X_train_vec.nnz / (X_train_vec.shape[0] * X_train_vec.shape[1]) * 100:.2f}%")
        
        # GridSearch (optional)
        if self.use_gridsearch:
            print("\n🔍 Running GridSearch (this may take 10-30 minutes)...")
            self._run_gridsearch(X_train_vec, y_train)
        
        # Train final model
        print("\n🏋️  Training final model (ElasticNet LR with feature selection)...")
        self.model.fit(X_train_vec, y_train)
        
        # Show sparsity from L1 regularization
        n_nonzero = np.sum(self.model.coef_ != 0)
        print(f"   Non-zero coefficients: {n_nonzero}/{X_train_vec.shape[1]} ({n_nonzero/X_train_vec.shape[1]*100:.1f}%)")
        
        # Evaluate
        self._evaluate(X_train_vec, y_train, X_val_vec, y_val, X_test_vec, y_test)
        
        # Save
        self._save_model()
    
    def _run_gridsearch(self, X_train, y_train):
        """GridSearch for optimal hyperparameters"""
        param_grid = {
            'C': [0.3, 0.5, 0.7, 1.0],
            'l1_ratio': [0.1, 0.3, 0.5, 0.7],
        }
        
        grid = GridSearchCV(
            LogisticRegression(
                max_iter=2000,
                class_weight='balanced',
                solver='saga',
                penalty='elasticnet',
                random_state=42,
                n_jobs=-1
            ),
            param_grid,
            cv=3,
            scoring='roc_auc',
            n_jobs=-1,
            verbose=2
        )
        
        grid.fit(X_train, y_train)
        
        print(f"\n   Best params: {grid.best_params_}")
        print(f"   Best CV AUC: {grid.best_score_:.4f}")
        
        # Update model with best params
        self.model.set_params(**grid.best_params_)
    
    def _evaluate(self, X_train, y_train, X_val, y_val, X_test, y_test):
        """Comprehensive evaluation"""
        # Train metrics
        train_probs = self.model.predict_proba(X_train)[:, 1]
        train_auc = roc_auc_score(y_train, train_probs)
        
        # Val metrics
        val_probs = self.model.predict_proba(X_val)[:, 1]
        val_auc = roc_auc_score(y_val, val_probs)
        
        # Test metrics
        test_probs = self.model.predict_proba(X_test)[:, 1]
        test_auc = roc_auc_score(y_test, test_probs)
        
        print(f"\n📈 AUC Scores:")
        print(f"   Train: {train_auc:.4f}")
        print(f"   Val:   {val_auc:.4f}")
        print(f"   Test:  {test_auc:.4f}")
        
        # Check for overfitting
        if train_auc - test_auc > 0.05:
            print(f"   ⚠️  Warning: Possible overfitting (train-test gap: {train_auc-test_auc:.4f})")
        
        # Find optimal thresholds
        precision, recall, thresholds = precision_recall_curve(y_val, val_probs)
        
        # Threshold 1: Maximize F1
        f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
        best_f1_idx = np.argmax(f1_scores[:-1])
        threshold_f1 = float(thresholds[best_f1_idx])
        
        # Threshold 2: High precision (blocking mode)
        high_prec_idx = np.where(precision[:-1] >= 0.95)[0]
        if len(high_prec_idx) > 0:
            threshold_blocking = float(thresholds[high_prec_idx[0]])
        else:
            threshold_blocking = 0.9
        
        # Threshold 3: High recall (hunting mode)
        high_rec_idx = np.where(recall[:-1] >= 0.95)[0]
        if len(high_rec_idx) > 0:
            threshold_hunting = float(thresholds[high_rec_idx[-1]])
        else:
            threshold_hunting = 0.3
        
        print(f"\n🎯 Optimal Thresholds (on validation set):")
        print(f"   F1-optimal:  {threshold_f1:.4f}")
        print(f"   Blocking:    {threshold_blocking:.4f} (precision ≥0.95)")
        print(f"   Hunting:     {threshold_hunting:.4f} (recall ≥0.95)")
        
        # Evaluate on test set with optimal threshold
        self.optimal_threshold = threshold_f1
        
        test_preds = (test_probs >= self.optimal_threshold).astype(int)
        
        print(f"\n📊 Test Set Performance (threshold={self.optimal_threshold:.4f}):")
        print(classification_report(y_test, test_preds, 
                                   target_names=['Clean', 'Webshell'],
                                   digits=4))
        
        cm = confusion_matrix(y_test, test_preds)
        fp_rate = cm[0,1] / (cm[0,0] + cm[0,1]) if (cm[0,0] + cm[0,1]) > 0 else 0
        fn_rate = cm[1,0] / (cm[1,0] + cm[1,1]) if (cm[1,0] + cm[1,1]) > 0 else 0
        
        print(f"\n   FP Rate: {fp_rate*100:.2f}%")
        print(f"   FN Rate: {fn_rate*100:.2f}%")
        
        self.test_metrics = {
            'auc': float(test_auc),
            'fp_rate': float(fp_rate),
            'fn_rate': float(fn_rate),
            'threshold_f1': float(threshold_f1),
            'threshold_blocking': float(threshold_blocking),
            'threshold_hunting': float(threshold_hunting),
        }
        
        # Top features
        self._show_top_features()
    
    def _show_top_features(self, top_n=30):
        """Show discriminative n-grams from both char and word"""
        print(f"\n🔍 Top {top_n} Discriminative Features:")
        
        # Get feature names from FeatureUnion
        char_features = self.vectorizer.transformer_list[0][1].get_feature_names_out()
        word_features = self.vectorizer.transformer_list[1][1].get_feature_names_out()
        
        all_features = np.concatenate([
            ['CHAR:' + f for f in char_features],
            ['WORD:' + f for f in word_features]
        ])
        
        coefficients = self.model.coef_[0]
        
        # Top webshell indicators
        print("\n   Webshell indicators:")
        top_indices = np.argsort(coefficients)[-top_n:][::-1]
        for idx in top_indices[:15]:
            feature = all_features[idx]
            coef = coefficients[idx]
            print(f"      {feature:50s} {coef:8.4f}")
        
        # Top clean indicators
        print("\n   Clean indicators:")
        bottom_indices = np.argsort(coefficients)[:top_n]
        for idx in bottom_indices[:15]:
            feature = all_features[idx]
            coef = coefficients[idx]
            print(f"      {feature:50s} {coef:8.4f}")
    
    def _save_model(self):
        """Save all artifacts"""
        model_path = os.path.join(self.output_dir, "ngram_model.joblib")
        vectorizer_path = os.path.join(self.output_dir, "ngram_vectorizer.joblib")
        meta_path = os.path.join(self.output_dir, "ngram_meta.json")
        
        joblib.dump(self.model, model_path)
        joblib.dump(self.vectorizer, vectorizer_path)
        
        # Get feature counts
        char_features = len(self.vectorizer.transformer_list[0][1].get_feature_names_out())
        word_features = len(self.vectorizer.transformer_list[1][1].get_feature_names_out())
        
        meta = {
            "threshold": float(self.optimal_threshold),
            "test_auc": self.test_metrics['auc'],
            "fp_rate": self.test_metrics['fp_rate'],
            "fn_rate": self.test_metrics['fn_rate'],
            "threshold_blocking": self.test_metrics['threshold_blocking'],
            "threshold_hunting": self.test_metrics['threshold_hunting'],
            "char_features": int(char_features),
            "word_features": int(word_features),
            "total_features": int(char_features + word_features),
            "char_ngram_range": self.vectorizer.transformer_list[0][1].ngram_range,
            "word_ngram_range": self.vectorizer.transformer_list[1][1].ngram_range,
            "version": "2.1-truly-hybrid",
        }
        
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)
        
        print(f"\n💾 Model saved:")
        print(f"   {model_path}")
        print(f"   {vectorizer_path}")
        print(f"   {meta_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Train truly optimized hybrid n-gram webshell detector"
    )
    parser.add_argument("--clean-dir", required=True)
    parser.add_argument("--webshell-dir", required=True)
    parser.add_argument("--output-dir", default="models")
    parser.add_argument("--gridsearch", action="store_true",
                       help="Run GridSearch for hyperparameter tuning (slow)")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.clean_dir):
        print(f"❌ Clean directory not found: {args.clean_dir}")
        sys.exit(1)
    
    if not os.path.isdir(args.webshell_dir):
        print(f"❌ Webshell directory not found: {args.webshell_dir}")
        sys.exit(1)
    
    trainer = TrulyOptimizedNgramTrainer(
        output_dir=args.output_dir,
        use_gridsearch=args.gridsearch
    )
    trainer.train(args.clean_dir, args.webshell_dir)
    
    print("\n✅ Training complete!")
    print("\n💡 Integration notes:")
    print("   - HYBRID char (3-6) + word (1-3) n-grams")
    print("   - Char analyzer catches <?php, $_, ::, -> patterns")
    print("   - Smart base64 length preservation")
    print("   - ElasticNet auto feature selection")
    print("   - Use 'threshold' for general detection")
    print("   - Use 'threshold_blocking' for low FP (production)")
    print("   - Use 'threshold_hunting' for low FN (investigation)")


if __name__ == "__main__":
    main()