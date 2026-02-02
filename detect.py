#!/usr/bin/env python3
"""
WEBSHELL SCANNER - ENHANCED FP/FN REDUCTION v8.0

Major improvements:
1. ASPX webshell detection (file manager, tunneling, WinAPI)
2. Stricter framework detection with behavior-based override
3. Reduced false positives on legitimate frameworks
4. Better handling of obfuscated patterns
5. Framework signature allowlist
"""

import os
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import joblib
import numpy as np

from extractor import WebshellFeatureExtractor


class WebshellScanner:
    def __init__(self, model_dir: str, mode: str = "hunting", scan_all: bool = False, output_dir: str = None, detector: str = "lgbm"):
        self.mode = mode
        self.scan_all = scan_all
        self.detector_mode = detector  # Multi-mode detection
        self.output_dir = output_dir
        self.extractor = WebshellFeatureExtractor()
        
        # Code markers for scan-all mode
        self.code_markers = [
            b'<?php', b'<?=',  # PHP
            b'<%@', b'<%=', b'runat="server"', b"runat='server'",  # ASPX
            b'using System', b'namespace ',  # C#
            b'function ', b'class ', b'var ', b'const ', b'let ',  # JavaScript
            b'import ', b'from ', b'def ', b'class ',  # Python/Java
            b'<%!', b'<%--',  # JSP
            b'eval(', b'exec(', b'system(',  # Execution
            b'base64_decode', b'gzinflate',  # Obfuscation
            b'$_GET', b'$_POST', b'$_REQUEST', b'$_COOKIE',  # Input
        ]
        
        if self.output_dir:
            os.makedirs(self.output_dir, exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "WEBSHELL"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "SUSPICIOUS"), exist_ok=True)
            os.makedirs(os.path.join(self.output_dir, "CLEAN"), exist_ok=True)

        # Load model
        if os.path.isfile(model_dir) and model_dir.endswith('.pkl'):
            print(f"⚠️  Loading legacy single .pkl file: {model_dir}")
            import pickle
            with open(model_dir, 'rb') as f:
                data = pickle.load(f)
            
            self.model = data['model']
            self.scaler = data['scaler']
            self.feature_names = data['feature_names']
            self.blocking_threshold = data.get('blocking_threshold', 0.9)
            self.hunting_threshold = data.get('hunting_threshold', 0.5)
            self.extractor_version = data.get('extractor_version', 'unknown')
            self.model_dir = os.path.dirname(model_dir)
        else:
            self.model_dir = model_dir
            model_path = os.path.join(model_dir, "webshell_model.joblib")
            scaler_path = os.path.join(model_dir, "webshell_scaler.joblib")
            meta_path = os.path.join(model_dir, "webshell_meta.json")
            
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model not found at {model_path}")
            
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)

            self.feature_names = meta["feature_names"]
            self.blocking_threshold = float(meta["blocking_threshold"])
            self.hunting_threshold = float(meta["hunting_threshold"])
            self.extractor_version = meta.get("extractor_version", "unknown")
            self.ngram_model = None
            self.ngram_vectorizer = None
            self.ngram_selector = None
            self.ngram_threshold = 0.5

            ngram_model_path = os.path.join(self.model_dir, "ngram_model.joblib")
            ngram_vectorizer_path = os.path.join(self.model_dir, "ngram_vectorizer.joblib")
            ngram_selector_path = os.path.join(self.model_dir, "ngram_selector.joblib")
            ngram_meta_path = os.path.join(self.model_dir, "ngram_meta.json")

            if os.path.exists(ngram_model_path) and os.path.exists(ngram_vectorizer_path):
                try:
                    self.ngram_model = joblib.load(ngram_model_path)
                    self.ngram_vectorizer = joblib.load(ngram_vectorizer_path)
                    
                    # Load feature selector (v2.0)
                    if os.path.exists(ngram_selector_path):
                        self.ngram_selector = joblib.load(ngram_selector_path)
                    
                    # Load optimal threshold
                    if os.path.exists(ngram_meta_path):
                        with open(ngram_meta_path, 'r') as f:
                            ngram_meta = json.load(f)
                        self.ngram_threshold = ngram_meta.get('threshold', 0.5)
                    
                    print(f"✅ N-gram model loaded (threshold: {self.ngram_threshold:.4f})")
                except Exception as e:
                    print(f"⚠️  N-gram model load failed: {e}")
                    self.ngram_model = None
            else:
                print("ℹ️  N-gram model not found (optional)")
        # Progressive thresholds
        if mode == "blocking":
            self.threshold = self.blocking_threshold
        else:
            self.threshold = min(self.hunting_threshold * 1.5, 0.55)
        
        self.suspicious_lower = self.threshold * 0.35
        self.suspicious_upper = self.threshold

        self.lock = Lock()
        self.stats = {"CLEAN": 0, "SUSPICIOUS": 0, "WEBSHELL": 0, "skipped": 0, "errors": 0}

    def _boost_behavioral_features(self, X):
        """Enhanced boosting for critical backdoor patterns"""
        # CRITICAL patterns
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
        
        # STRONG patterns
        strong_keys = {
            "behavior_cookie_hash_gate_dyn_call",
            "behavior_aspx_tunneling",
            "behavior_jsp_http_tunneling",
            "behavior_jsp_http_backdoor",  # ← THÊM
            "has_superglobal_var_call",
            "behavior_filterinput_exec",
            "behavior_arbitrary_upload_path",
            "behavior_file_manager",  # ← ĐÃ THÊM Ở FIX TRƯỚC
        }
        
        critical_indices = [i for i, name in enumerate(self.feature_names) if name in critical_keys]
        strong_indices = [i for i, name in enumerate(self.feature_names) if name in strong_keys]

        X_boosted = X.copy()
        if critical_indices:
            X_boosted[:, critical_indices] *= 1.8
        if strong_indices:
            X_boosted[:, strong_indices] *= 1.4
        return X_boosted

    def _update_stats(self, verdict: str):
        with self.lock:
            self.stats[verdict] += 1

    def _note_error(self, filepath: str, err: Exception):
        with self.lock:
            self.stats["errors"] += 1
            if self.stats["errors"] <= 10:
                print(f"❌ Error processing {filepath}: {type(err).__name__}: {err}")

    def _looks_like_code(self, filepath: str) -> bool:
        """
        Check if file contains code markers (for scan-all mode).
        Reduces FP on binary/data files when scanning everything.
        """
        try:
            with open(filepath, 'rb') as f:
                # Read first 2KB - enough to detect code markers
                header = f.read(2048)
            
            # Check for code markers
            for marker in self.code_markers:
                if marker in header:
                    return True
            
            # Check for high ASCII ratio (likely text/code)
            if len(header) > 0:
                ascii_count = sum(1 for b in header if 32 <= b <= 126 or b in (9, 10, 13))
                ascii_ratio = ascii_count / len(header)
                # If >70% ASCII, probably text/code
                if ascii_ratio > 0.7:
                    return True
            
            return False
        except:
            return False
        if not self.output_dir:
            return
            
        try:
            import shutil
            filename = os.path.basename(filepath)
            dest_dir = os.path.join(self.output_dir, verdict)
            dest_path = os.path.join(dest_dir, filename)
            
            counter = 1
            base, ext = os.path.splitext(filename)
            while os.path.exists(dest_path):
                dest_path = os.path.join(dest_dir, f"{base}_{counter}{ext}")
                counter += 1
            
            shutil.copy2(filepath, dest_path)
        except:
            pass
    def _export_file(self, filepath: str, verdict: str):
        """Export file to output directory by verdict"""
        if not self.output_dir:
            return
            
        try:
            import shutil
            filename = os.path.basename(filepath)
            dest_dir = os.path.join(self.output_dir, verdict)
            dest_path = os.path.join(dest_dir, filename)
            
            counter = 1
            base, ext = os.path.splitext(filename)
            while os.path.exists(dest_path):
                dest_path = os.path.join(dest_dir, f"{base}_{counter}{ext}")
                counter += 1
            
            shutil.copy2(filepath, dest_path)
        except:
            pass
    def _is_likely_framework(self, filepath: str, code: str, features: dict) -> bool:
        """Enhanced framework detection with behavior-based override"""
        
        # Check 1: Known framework signature (NEW)
        detected_framework = features.get("detected_framework", "")
        if detected_framework:
            # But verify no webshell behaviors present
            has_webshell_behaviors = self._has_webshell_behaviors(features, filepath)
            if has_webshell_behaviors:
                return False  # Framework code with webshell = not benign
            return True
        
        # Check 2: File size (frameworks are usually large)
        try:
            size = os.path.getsize(filepath)
            if size > 100_000:  # > 100KB
                # Large files still need behavior check
                if self._has_strong_webshell_behaviors(features, filepath):
                    return False
                return True
        except:
            pass
        
        # Check 3: High entropy + no dangerous patterns
        entropy = float(features.get("entropy", 0.0) or 0.0)
        has_exec = bool(features.get("has_exec_function", 0))
        has_input = bool(features.get("has_input_access", 0))
        has_decode = bool(features.get("has_decode_function", 0))
        
        # ASPX-specific: databinding Eval is OK
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ['.aspx', '.ascx', '.asax']:
            aspx_databinding_eval = int(features.get("aspx_databinding_eval_count", 0))
            aspx_code_eval = int(features.get("aspx_code_eval_count", 0))
            # If only databinding evals, reduce exec signal
            if aspx_databinding_eval > 0 and aspx_code_eval == 0:
                has_exec = False
        
        # Minified JS/CSS: high entropy but no backdoor patterns
        if entropy > 4.5 and not (has_exec and has_input):
            return True
        
        # Check 4: High string literal ratio
        str_ratio = float(features.get("string_literal_ratio", 0.0) or 0.0)
        if str_ratio > 0.75:
            # FIXED: But check for webshell behaviors first
            if self._has_webshell_behaviors(features, filepath):
                return False
            return True
        
        # Check 5: Very high blob score
        blob_score = float(features.get("benign_data_blob_score", 0.0) or 0.0)
        if blob_score > 0.8:
            return True
        
        # Check 6: Framework signatures in code
        if code:
            code_lower = code.lower()
            framework_signs = [
                'jquery', 'angular', 'react', 'vue', 'bootstrap', 
                'lodash', 'moment', 'axios', 'webpack', 'babel',
                '/*!', '* @license', '@preserve', 'copyright',
                'use strict', 'define.amd', 'exports.', 'module.exports'
            ]
            matches = sum(1 for sign in framework_signs if sign in code_lower)
            if matches >= 3:
                return True
        
        return False

    def _has_webshell_behaviors(self, features: dict, filepath: str) -> bool:
        """Check if file has ANY webshell behavior indicators"""
        ext = os.path.splitext(filepath)[1].lower()
        
        # PHP webshell behaviors
        php_behaviors = (
            features.get("behavior_input_decode_exec", 0) or
            features.get("behavior_password_backdoor", 0) or
            features.get("behavior_upload_chmod", 0) or
            features.get("behavior_cookie_hash_gate_dyn_call", 0) or
            features.get("has_superglobal_var_call", 0) or
            features.get("behavior_arbitrary_upload_path", 0) or
            features.get("behavior_sqlmap_uploader", 0) or
            features.get("behavior_filterinput_exec", 0) or
            features.get("behavior_file_manager", 0) 
        )
        
        # ASPX webshell behaviors
        aspx_behaviors = (
            features.get("behavior_aspx_process_shell", 0) or
            features.get("behavior_aspx_file_manager", 0) or
            features.get("behavior_aspx_tunneling", 0) or
            features.get("behavior_aspx_privilege_pipe", 0) or
            features.get("behavior_jscript_webshell", 0) or      # NEW
            features.get("behavior_dotnet_memory_shell", 0)      # NEW
        )
        jsp_behaviors = (
            features.get("behavior_jsp_memory_shell", 0) or
            features.get("behavior_jsp_request_exec", 0) or
            features.get("behavior_jsp_http_tunneling", 0)
        )
        # Generic webshell behaviors
        generic_behaviors = (
            features.get("behavior_reverse_shell", 0) or
            features.get("behavior_rawbody_backdoor", 0)
        )
        
        if ext in ['.jsp', '.jspx', '.java']:
            return bool(jsp_behaviors or generic_behaviors)
        elif ext in ['.aspx', '.ascx', '.asax', '.ashx']:
            return bool(aspx_behaviors or generic_behaviors)
        else:
            return bool(php_behaviors or generic_behaviors)

    def _has_strong_webshell_behaviors(self, features: dict, filepath: str) -> bool:
        """Check for STRONG webshell behavior indicators"""
        ext = os.path.splitext(filepath)[1].lower()
        
        # Critical PHP patterns
        php_critical = (
            features.get("behavior_input_decode_exec", 0) or
            features.get("behavior_password_backdoor", 0) or
            features.get("behavior_cookie_hash_gate_dyn_call", 0) or
            features.get("has_superglobal_var_call", 0) or
            (features.get("behavior_file_manager", 0) and 
         features.get("behavior_password_backdoor", 0))
        )
        
        # Critical ASPX patterns
        aspx_critical = (
            features.get("behavior_aspx_process_shell", 0) or
            features.get("behavior_aspx_privilege_pipe", 0) or
            features.get("behavior_aspx_tunneling", 0) or
            features.get("behavior_jscript_webshell", 0) or      # NEW
            features.get("behavior_dotnet_memory_shell", 0)      # NEW
        )
        # Critical JSP patterns
        jsp_critical = (
            features.get("behavior_jsp_memory_shell", 0) or
            features.get("behavior_jsp_request_exec", 0) or
            features.get("behavior_jsp_hardcoded_backdoor", 0) or  # ← THÊM
            features.get("behavior_jsp_http_backdoor", 0)          # ← THÊM
        )
        
        if ext in ['.jsp', '.jspx', '.java']:
            return bool(jsp_critical)
        elif ext in ['.aspx', '.ascx', '.asax', '.ashx']:
            return bool(aspx_critical)
        else:
            return bool(php_critical)

    def _calculate_confidence(self, prob: float, features: dict, is_framework: bool, filepath: str) -> float:
        """Enhanced confidence calculation with ASPX and JSP awareness"""
        confidence = 0.5
        
        ext = os.path.splitext(filepath)[1].lower()
        is_aspx = ext in ['.aspx', '.ascx', '.asax', '.ashx']
        is_jsp = ext in ['.jsp', '.jspx', '.java']
        
        # Framework files get low confidence automatically
        if is_framework:
            confidence -= 0.3
        
        # Strong indicators (PHP)
        if features.get("behavior_cookie_hash_gate_dyn_call", 0):
            confidence += 0.20
        if features.get("has_superglobal_var_call", 0):
            confidence += 0.15
        if features.get("behavior_password_backdoor", 0):
            confidence += 0.15
        if features.get("behavior_input_decode_exec", 0):
            confidence += 0.12
        
        # Strong indicators (ASPX)
        if features.get("behavior_aspx_process_shell", 0):
            confidence += 0.25
        if features.get("behavior_jscript_webshell", 0):
            confidence += 0.35  # Very specific signature
        if features.get("behavior_dotnet_memory_shell", 0):
            confidence += 0.35  # Very specific signature    
        if features.get("behavior_aspx_privilege_pipe", 0):
            confidence += 0.30
        if features.get("behavior_aspx_tunneling", 0):
            confidence += 0.28
        if features.get("behavior_aspx_file_manager", 0):
            confidence += 0.18
        
        # Strong indicators (JSP) - NEW
        if features.get("behavior_jsp_memory_shell", 0):
            confidence += 0.35  # Memory shells are very suspicious
        if features.get("behavior_jsp_request_exec", 0):
            confidence += 0.28
        if features.get("behavior_jsp_http_tunneling", 0):
            confidence += 0.25
        if features.get("behavior_jsp_hardcoded_backdoor", 0):
            confidence += 0.40  # Hardcoded backdoor command is very specific
        if features.get("behavior_jsp_http_backdoor", 0):
            confidence += 0.35  # HTTP to suspicious domain
            
        # Benign indicators
        blob_score = float(features.get("benign_data_blob_score", 0.0) or 0.0)
        if blob_score > 0.4:
            confidence -= 0.25
        if blob_score > 0.7:
            confidence -= 0.20
            
        str_ratio = float(features.get("string_literal_ratio", 0.0) or 0.0)
        # ASPX/JSP: high string ratio is more normal
        if is_aspx or is_jsp:
            if str_ratio > 0.85:
                confidence -= 0.15
        else:
            if str_ratio > 0.7:
                confidence -= 0.20
        
        # Low threat score
        threat_score = float(features.get("overall_threat_score", 0.0) or 0.0)
        if threat_score < 0.2:
            confidence -= 0.15
            
        return max(0.0, min(1.0, confidence))

    def scan_file(self, filepath: str):
        try:
            ext = os.path.splitext(filepath)[1].lower()
            
            # Scan-all mode with code detection gate
            if self.scan_all:
                # Ambiguous extensions need code markers
                ambiguous_exts = {".txt", ".config", ".log", ".dat", ".bak", ""}
                if ext in ambiguous_exts:
                    if not self._looks_like_code(filepath):
                        with self.lock:
                            if 'skipped_no_code' not in self.stats:
                                self.stats['skipped_no_code'] = 0
                            self.stats['skipped_no_code'] += 1
                        return None
            else:
                # Normal mode: only scan known code extensions
                if ext not in {".php", ".asp", ".aspx", ".jsp", ".jspx", ".py", ".js", ".txt", 
                              ".cs", ".config", ".inc", ".phtml", ".cgi", ".pl", ".ascx", 
                              ".asax", ".ashx", ".asmx", ""}:
                    with self.lock:
                        if 'skipped_by_ext' not in self.stats:
                            self.stats['skipped_by_ext'] = 0
                        self.stats['skipped_by_ext'] += 1
                    return None

            code = self.extractor.safe_read(filepath)
            
            if not code or len(code) < 20:
                with self.lock:
                    self.stats["skipped"] += 1
                return None

            feats = self.extractor.extract_features_from_code(code, filepath)
            if not feats:
                with self.lock:
                    self.stats["skipped"] += 1
                return None

            feats.pop("_version", None)
            feats.pop("_group_id", None)
            detected_framework = feats.pop("detected_framework", "")

            # Align features
            x_dict = {k: float(feats.get(k, 0.0)) if not isinstance(feats.get(k), str) else 0.0 
                     for k in self.feature_names}
            
            if not hasattr(self, '_warned_missing'):
                missing = [k for k in self.feature_names if k not in feats]
                if missing:
                    print(f"\n⚠️  WARNING: {len(missing)} features missing from extractor")
                self._warned_missing = True
            
            x = np.array([x_dict[k] for k in self.feature_names], dtype=np.float32).reshape(1, -1)

            # Boost behavioral features
            x = self._boost_behavioral_features(x)
            X_scaled = self.scaler.transform(x)
            prob_lgbm = float(self.model.predict_proba(X_scaled)[0][1])

            # ========== THÊM ĐOẠN NÀY ==========
            # N-gram prediction
            prob_ngram = 0.0
            if self.ngram_model is not None and code:
                try:
                    # Preprocess (same as training)
                    code_clean = code.replace('\x00', '')
                    if len(code_clean) > 80000:
                        code_clean = code_clean[:80000]
                    
                    # Transform
                    code_tfidf = self.ngram_vectorizer.transform([code_clean])
                    
                    # Feature selection (if v2.0)
                    if self.ngram_selector is not None:
                        code_tfidf = self.ngram_selector.transform(code_tfidf)
                    
                    # Predict
                    prob_ngram = float(self.ngram_model.predict_proba(code_tfidf)[0][1])
                except:
                    prob_ngram = 0.0

            # Ensemble: weighted average
            if self.ngram_model is not None:
                prob = 0.75 * prob_lgbm + 0.25 * prob_ngram
            else:
                prob = prob_lgbm
            # ========== KẾT THÚC ĐOẠN THÊM ==========

            # Framework detection
            is_framework = self._is_likely_framework(filepath, code, feats)
            
            # Calculate confidence
            confidence = self._calculate_confidence(prob, feats, is_framework, filepath)
            
            # Extract key features
            blob_score = float(feats.get("benign_data_blob_score", 0.0) or 0.0)
            threat_score = float(feats.get("overall_threat_score", 0.0) or 0.0)
            str_ratio = float(feats.get("string_literal_ratio", 0.0) or 0.0)
            entropy = float(feats.get("entropy", 0.0) or 0.0)
            
            has_exec = bool(feats.get("has_exec_function", 0))
            has_input = bool(feats.get("has_input_access", 0))
            has_decode = bool(feats.get("has_decode_function", 0))
            
            # Check for strong backdoor patterns
            has_strong_backdoor = bool(
                feats.get("behavior_cookie_hash_gate_dyn_call", 0) or
                feats.get("behavior_aspx_process_shell", 0) or
                feats.get("behavior_aspx_privilege_pipe", 0) or
                feats.get("behavior_jsp_memory_shell", 0) or
                feats.get("behavior_jsp_request_exec", 0) or
                feats.get("behavior_jsp_hardcoded_backdoor", 0) or  # ← THÊM
                feats.get("behavior_jsp_http_backdoor", 0) or       # ← THÊM
                feats.get("behavior_jscript_webshell", 0) or
                feats.get("behavior_dotnet_memory_shell", 0) or
                feats.get("has_superglobal_var_call", 0) or
                feats.get("behavior_input_decode_exec", 0) or
                feats.get("behavior_password_backdoor", 0)
            )
            
            has_medium_backdoor = bool(
                feats.get("has_assign_input_then_call", 0) or
                feats.get("behavior_upload_chmod", 0) or
                feats.get("behavior_aspx_file_manager", 0) or
                feats.get("behavior_aspx_tunneling", 0) or
                feats.get("behavior_jsp_http_tunneling", 0) or
                feats.get("behavior_file_manager", 0) or  # ← ĐÃ THÊM Ở FIX TRƯỚC
                (has_exec and has_input) or
                (has_decode and has_input)
            )

            # === ENHANCED CLASSIFICATION LOGIC ===
            verdict = "CLEAN"
            is_aspx = ext in ['.aspx', '.ascx', '.asax', '.ashx']
            is_jsp = ext in ['.jsp', '.jspx', '.java']
            if (feats.get("behavior_jscript_webshell", 0) or 
                feats.get("behavior_dotnet_memory_shell", 0)):
                # These are extremely specific - high confidence even with low prob
                if prob >= (self.threshold * 0.4):
                    verdict = "WEBSHELL"
                elif prob >= (self.threshold * 0.2):
                    verdict = "SUSPICIOUS"
                else:
                    # Strong signature but low prob - still flag as suspicious
                    verdict = "SUSPICIOUS" if confidence > 0.3 else "CLEAN"
            # VETO 1: Framework files with behavior-based override
            elif is_framework:
                if has_strong_backdoor:
                    # Strong behaviors override framework status
                    if prob >= (self.threshold * 1.2):
                        verdict = "WEBSHELL"
                    elif prob >= (self.threshold * 0.8):
                        verdict = "SUSPICIOUS"
                    else:
                        verdict = "CLEAN"
                elif has_medium_backdoor:
                    if prob >= (self.threshold * 1.5):
                        verdict = "SUSPICIOUS"
                    else:
                        verdict = "CLEAN"
                elif prob >= (self.threshold * 2.5):
                    # High prob without clear behaviors
                    if threat_score < 0.2:
                        verdict = "CLEAN"
                    else:
                        verdict = "SUSPICIOUS"
                else:
                    verdict = "CLEAN"
            
            # VETO 2: High blob score = likely benign data
            elif blob_score > 0.6 and threat_score < 0.3:
                verdict = "CLEAN"
            
            # VETO 3: JS/CSS files with special handling
            elif ext in ['.js', '.css']:
                if has_strong_backdoor and prob >= (self.threshold * 2.0):
                    verdict = "WEBSHELL"
                elif has_strong_backdoor and prob >= (self.threshold * 1.5):
                    verdict = "SUSPICIOUS"
                elif has_medium_backdoor and prob >= (self.threshold * 2.2):
                    verdict = "SUSPICIOUS"
                elif prob >= (self.threshold * 2.5):
                    if threat_score < 0.2:
                        verdict = "CLEAN"
                    else:
                        verdict = "SUSPICIOUS"
                else:
                    verdict = "CLEAN"
            
            # Normal classification for other files
            else:
                # Tier 0: CRITICAL patterns
                if has_strong_backdoor or has_medium_backdoor:
                    if prob >= (self.threshold * 0.6):
                        verdict = "WEBSHELL"
                    elif prob >= (self.threshold * 0.4):
                        verdict = "SUSPICIOUS"
                    else:
                        verdict = "CLEAN"
                
                # Tier 1: Very high probability
                elif prob >= (self.threshold * 1.8):
                    if blob_score > 0.5 or threat_score < 0.3:
                        verdict = "SUSPICIOUS"
                    else:
                        verdict = "WEBSHELL"
                
                # Tier 2: High probability with validation
                elif prob >= (self.threshold * 1.3):
                    if threat_score > 0.3:
                        verdict = "WEBSHELL"
                    elif blob_score < 0.4:
                        verdict = "SUSPICIOUS"
                    else:
                        verdict = "CLEAN"
                
                # Tier 3: Suspicious zone
                elif prob >= self.suspicious_lower:
                    if threat_score > 0.35 and confidence > 0.4:
                        verdict = "SUSPICIOUS"
                    else:
                        verdict = "CLEAN"
                
                else:
                    verdict = "CLEAN"

            # Final safety check for hunting mode
            if self.mode == "hunting" and verdict == "WEBSHELL":
                if confidence < 0.35:
                    verdict = "SUSPICIOUS"
                elif is_framework or blob_score > 0.5:
                    verdict = "SUSPICIOUS"

            self._update_stats(verdict)
            self._export_file(filepath, verdict)

            return {
                "file": filepath,
                "extension": ext,
                "probability": round(prob, 4),
                "probability_lgbm": round(prob_lgbm, 4),      # ← THÊM
                "probability_ngram": round(prob_ngram, 4),    # ← THÊM
                "confidence": round(confidence, 4),
                "verdict": verdict,
                "blob_score": round(blob_score, 4),
                "threat_score": round(threat_score, 4),
                "is_framework": is_framework,
                "detected_framework": detected_framework,
            }

        except Exception as e:
            self._note_error(filepath, e)
            if self.stats["errors"] == 1:
                import traceback
                print(f"\n🔍 First error traceback:")
                traceback.print_exc()
            return None

    def scan_directory(self, root_dir: str):
        files = []
        for root, _, names in os.walk(root_dir):
            files.extend(os.path.join(root, n) for n in names)

        results = []
        with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as ex:
            futures = [ex.submit(self.scan_file, fp) for fp in files]
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    results.append(r)

        return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="Directory to scan")
    ap.add_argument("--model-dir", default="models", help="Model directory")
    ap.add_argument("--mode", choices=["hunting", "blocking"], default="hunting", help="Detection mode")
    ap.add_argument("--detector", choices=["lgbm", "ngram", "ensemble"], default="lgbm", help="Detector type")
    ap.add_argument("--show-confidence", action="store_true", help="Show confidence scores")
    ap.add_argument("--show-framework", action="store_true", help="Show detected frameworks")
    ap.add_argument("--scan-all", action="store_true", help="Scan ALL files")
    ap.add_argument("--output-dir", help="Export files to directory")
    ap.add_argument("--output-json", help="Save results to JSON")
    ap.add_argument("--show-ngram", action="store_true", help="Show n-gram scores")
    args = ap.parse_args()

    scanner = WebshellScanner(args.model_dir, args.mode, args.scan_all, args.output_dir, args.detector)

    print(f"🔌 Mode: {args.mode}")
    print(f"🔌 Scan Mode: {'ALL_FILES' if args.scan_all else 'CODE_ONLY'}")
    print(f"🔌 Base Threshold: {scanner.hunting_threshold:.4f}")
    print(f"🔌 Adjusted Threshold: {scanner.threshold:.4f}")
    print(f"🔌 Suspicious Zone: {scanner.suspicious_lower:.4f} - {scanner.suspicious_upper:.4f}")
    
    if args.output_dir:
        print(f"📁 Output Directory: {args.output_dir}")

    results = scanner.scan_directory(args.dir)

    print("\n=== STATS ===")
    for k, v in scanner.stats.items():
        print(f"{k:20s}: {v}")

    total_detections = scanner.stats["WEBSHELL"] + scanner.stats["SUSPICIOUS"]
    total_scanned = scanner.stats["CLEAN"] + total_detections
    skipped_by_ext = scanner.stats.get('skipped_by_ext', 0)
    skipped_no_code = scanner.stats.get('skipped_no_code', 0)
    
    if total_scanned > 0:
        detection_rate = (total_detections / total_scanned) * 100
        webshell_rate = (scanner.stats["WEBSHELL"] / total_scanned) * 100
        print(f"\nDetection Rate : {detection_rate:.2f}%")
        print(f"Webshell Rate  : {webshell_rate:.2f}%")
        print(f"Total Processed: {total_scanned}")
        print(f"Skipped (size) : {scanner.stats['skipped']}")
        print(f"Skipped (ext)  : {skipped_by_ext}")
        print(f"Skipped (no code): {skipped_no_code}")
        print(f"Errors         : {scanner.stats['errors']}")
        
        total_files = total_scanned + scanner.stats['skipped'] + skipped_by_ext + skipped_no_code + scanner.stats['errors']
        coverage = (total_scanned / total_files * 100) if total_files > 0 else 0
        print(f"Total Files    : {total_files}")
        print(f"Coverage       : {coverage:.2f}%")

    results_sorted = sorted(results, key=lambda x: x["probability"], reverse=True)
    print("\n=== TOP 50 RESULTS ===")

    if args.show_ngram:  # ← THÊM ĐIỀU KIỆN NÀY
        print("PROB    LGBM    NGRAM   CONF    VERDICT      FILE")
    elif args.show_framework:
        print("PROB    CONF    VERDICT      BLOB   THREAT  FW   FRAMEWORK      FILE")
    elif args.show_confidence:
        print("PROB    CONF    VERDICT      BLOB   THREAT  FW   FILE")
    else:
        print("PROB    VERDICT      FILE")
    print("=" * 100)
    
    for r in results_sorted[:50]:
        fw_marker = "✓" if r.get("is_framework") else " "
        fw_name = r.get("detected_framework", "")[:12]
        
        # ← THÊM ĐIỀU KIỆN NÀY
        if args.show_ngram:
            print(f'{r["probability"]:.4f}  {r.get("probability_lgbm", 0):.4f}  '
                f'{r.get("probability_ngram", 0):.4f}  {r["confidence"]:.4f}  '
                f'{r["verdict"]:12s}  {r["file"]}')
        elif args.show_framework:
            print(f'{r["probability"]:.4f}  {r["confidence"]:.4f}  {r["verdict"]:12s} '
                f'{r["blob_score"]:.4f} {r["threat_score"]:.4f}  {fw_marker}   '
                f'{fw_name:14s} {r["file"]}')
        elif args.show_confidence:
            print(f'{r["probability"]:.4f}  {r["confidence"]:.4f}  {r["verdict"]:12s} '
                f'{r["blob_score"]:.4f} {r["threat_score"]:.4f}  {fw_marker}   {r["file"]}')
        else:
            print(f'{r["probability"]:.4f}  {r["verdict"]:12s}  {r["file"]}')
    
    if args.output_json:
        import json
        report = {
            "scan_time": str(__import__('datetime').datetime.now()),
            "mode": args.mode,
            "threshold": scanner.threshold,
            "stats": scanner.stats,
            "results": results_sorted
        }
        with open(args.output_json, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n💾 Results saved to: {args.output_json}")
    
    if args.output_dir:
        print(f"\n📂 Files exported to:")
        print(f"   {args.output_dir}/WEBSHELL/    - {scanner.stats['WEBSHELL']} files")
        print(f"   {args.output_dir}/SUSPICIOUS/  - {scanner.stats['SUSPICIOUS']} files")
        print(f"   {args.output_dir}/CLEAN/       - {scanner.stats['CLEAN']} files")


if __name__ == "__main__":
    main()