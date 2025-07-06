"""CodeBERT embeddings for code analysis."""

import hashlib
import logging
import weakref
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import CodeEmbedding

logger = logging.getLogger(__name__)


class LRUCache:
    """Thread-safe LRU cache implementation for embeddings."""
    
    def __init__(self, max_size: int):
        """Initialize LRU cache.
        
        Args:
            max_size: Maximum number of items to cache
        """
        self.max_size = max_size
        self._cache = OrderedDict()
        self._lock = None
        
    def get(self, key: str) -> Optional[CodeEmbedding]:
        """Get item from cache, updating access order.
        
        Args:
            key: Cache key
            
        Returns:
            Cached item or None
        """
        if key not in self._cache:
            return None
            
        # Move to end (most recently used)
        self._cache.move_to_end(key)
        return self._cache[key]
    
    def put(self, key: str, value: CodeEmbedding) -> None:
        """Put item in cache, evicting LRU item if necessary.
        
        Args:
            key: Cache key
            value: Value to cache
        """
        if key in self._cache:
            # Update existing and move to end
            self._cache.move_to_end(key)
            self._cache[key] = value
            return
            
        # Add new item
        self._cache[key] = value
        
        # Evict LRU items if cache is full
        while len(self._cache) > self.max_size:
            # Remove least recently used (first item)
            evicted_key = next(iter(self._cache))
            del self._cache[evicted_key]
            logger.debug(f"Evicted LRU cache entry: {evicted_key[:8]}...")
    
    def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
    
    def __len__(self) -> int:
        """Get number of cached items."""
        return len(self._cache)
    
    def __contains__(self, key: str) -> bool:
        """Check if key is in cache."""
        return key in self._cache


class ModelRegistry:
    """Singleton registry for managing shared models with proper cleanup."""
    
    _instance = None
    _models = {}
    _model_refs = {}
    _lock = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            import threading
            cls._lock = threading.Lock()
        return cls._instance
    
    def get_model(self, model_name: str, device: torch.device) -> Tuple[AutoTokenizer, AutoModel]:
        """Get or create model with reference counting.
        
        Args:
            model_name: Name of the model
            device: Device to load model on
            
        Returns:
            Tuple of (tokenizer, model)
        """
        cache_key = f"{model_name}:{device}"
        
        with self._lock:
            if cache_key in self._models:
                # Model exists, increment reference count
                self._model_refs[cache_key] = self._model_refs.get(cache_key, 0) + 1
                model_data = self._models[cache_key]
                logger.debug(f"Reusing cached model {model_name}, refs: {self._model_refs[cache_key]}")
                return model_data["tokenizer"], model_data["model"]
            
            # Load new model
            logger.info(f"Loading new model: {model_name}")
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            model = AutoModel.from_pretrained(model_name)
            model.to(device)
            model.eval()
            
            # Cache with reference count
            self._models[cache_key] = {
                "tokenizer": tokenizer,
                "model": model,
                "device": device,
                "loaded_at": datetime.now()
            }
            self._model_refs[cache_key] = 1
            
            return tokenizer, model
    
    def release_model(self, model_name: str, device: torch.device) -> None:
        """Release model reference, cleaning up if no references remain.
        
        Args:
            model_name: Name of the model
            device: Device model is on
        """
        cache_key = f"{model_name}:{device}"
        
        with self._lock:
            if cache_key not in self._model_refs:
                return
                
            self._model_refs[cache_key] -= 1
            logger.debug(f"Released model {model_name}, refs: {self._model_refs[cache_key]}")
            
            # Clean up if no more references
            if self._model_refs[cache_key] <= 0:
                if cache_key in self._models:
                    model_data = self._models[cache_key]
                    # Move model to CPU and delete to free GPU memory
                    model_data["model"].cpu()
                    del model_data["model"]
                    del self._models[cache_key]
                    del self._model_refs[cache_key]
                    
                    # Force garbage collection for GPU memory
                    if device.type == "cuda":
                        torch.cuda.empty_cache()
                    
                    logger.info(f"Cleaned up model {model_name} from {device}")
    
    def cleanup_all(self) -> None:
        """Clean up all cached models."""
        with self._lock:
            for cache_key, model_data in list(self._models.items()):
                if "model" in model_data:
                    model_data["model"].cpu()
                    del model_data["model"]
            
            self._models.clear()
            self._model_refs.clear()
            
            # Force garbage collection
            torch.cuda.empty_cache() if torch.cuda.is_available() else None
            logger.info("Cleaned up all cached models")


class CodeBERTEmbedder:
    """CodeBERT-based code embeddings generator with proper memory management."""
    
    # Shared model registry
    _model_registry = None

    def __init__(self, config: Optional[Config] = None):
        """Initialize CodeBERT embedder.

        Args:
            config: Configuration object
        """
        self.config = config or Config.from_env()
        self.model_name = "microsoft/codebert-base"
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Use LRU cache for embeddings
        self.cache_size_limit = getattr(self.config, 'embedding_cache_size', 1000)
        self.embedding_cache = LRUCache(self.cache_size_limit)
        
        # Initialize model registry
        if CodeBERTEmbedder._model_registry is None:
            CodeBERTEmbedder._model_registry = ModelRegistry()
        
        # Initialize model reference
        self.tokenizer = None
        self.model = None
        self._model_loaded = False
        
        # Keep weak reference to embedder for cleanup
        self._finalizer = weakref.finalize(self, self._cleanup_resources)

    def _ensure_model_loaded(self) -> None:
        """Ensure model is loaded using the model registry."""
        if self._model_loaded:
            return
            
        try:
            self.tokenizer, self.model = self._model_registry.get_model(self.model_name, self.device)
            self._model_loaded = True
        except Exception as e:
            logger.error(f"Error loading CodeBERT model: {e}")
            raise
    
    def _cleanup_resources(self) -> None:
        """Clean up resources when embedder is garbage collected."""
        try:
            # Release model reference
            if self._model_loaded and self._model_registry:
                self._model_registry.release_model(self.model_name, self.device)
                logger.debug(f"Released model reference for {self.model_name}")
            
            # Clear embedding cache
            if hasattr(self, 'embedding_cache'):
                self.embedding_cache.clear()
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Destructor to ensure cleanup."""
        self._cleanup_resources()

    def generate_embedding(self, code: str, language: str = "python") -> CodeEmbedding:
        """Generate embedding for code snippet.

        Args:
            code: Source code to embed
            language: Programming language

        Returns:
            CodeEmbedding object
        """
        # Ensure model is loaded
        self._ensure_model_loaded()
        
        # Generate hash for caching
        code_hash = self._generate_code_hash(code)

        # Check cache
        cached_embedding = self.embedding_cache.get(code_hash)
        if cached_embedding:
            logger.debug(f"Using cached embedding for code hash: {code_hash[:8]}...")
            return cached_embedding

        # Generate embedding
        embedding = self._create_embedding(code, language)

        # Create CodeEmbedding object
        code_embedding = CodeEmbedding(
            code_hash=code_hash,
            embedding=embedding.tolist(),
            model_name=self.model_name,
            model_version="1.0.0",
            created_at=datetime.now(),
        )

        # Cache the embedding
        self.embedding_cache.put(code_hash, code_embedding)

        return code_embedding

    def _create_embedding(self, code: str, language: str) -> np.ndarray:
        """Create embedding using CodeBERT.

        Args:
            code: Source code
            language: Programming language

        Returns:
            Embedding vector as numpy array
        """
        try:
            # Preprocess code
            processed_code = self._preprocess_code(code, language)

            # Tokenize
            inputs = self.tokenizer(
                processed_code, return_tensors="pt", max_length=512, truncation=True, padding=True
            )

            # Move to device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            # Generate embedding
            with torch.no_grad():
                outputs = self.model(**inputs)

                # Use pooled output or mean of last hidden states
                if hasattr(outputs, "pooler_output") and outputs.pooler_output is not None:
                    embedding = outputs.pooler_output
                else:
                    # Use mean of last hidden states
                    embedding = outputs.last_hidden_state.mean(dim=1)

                # Convert to numpy
                embedding = embedding.cpu().numpy().flatten()

            return embedding

        except Exception as e:
            logger.error(f"Error creating embedding: {e}")
            # Return zero vector as fallback
            return np.zeros(768)  # CodeBERT hidden size

    def _preprocess_code(self, code: str, language: str) -> str:
        """Preprocess code for embedding generation.

        Args:
            code: Source code
            language: Programming language

        Returns:
            Preprocessed code
        """
        # Remove excessive whitespace
        lines = code.split("\n")
        processed_lines = []

        for line in lines:
            # Remove leading/trailing whitespace
            line = line.strip()

            # Skip empty lines
            if not line:
                continue

            # Skip comments (basic implementation)
            if language == "python" and line.startswith("#"):
                continue
            elif language == "javascript" and line.startswith("//"):
                continue

            processed_lines.append(line)

        return "\n".join(processed_lines)

    def _generate_code_hash(self, code: str) -> str:
        """Generate hash for code snippet.

        Args:
            code: Source code

        Returns:
            SHA-256 hash of the code
        """
        return hashlib.sha256(code.encode("utf-8")).hexdigest()


    def similarity(self, embedding1: CodeEmbedding, embedding2: CodeEmbedding) -> float:
        """Calculate cosine similarity between two embeddings.

        Args:
            embedding1: First embedding
            embedding2: Second embedding

        Returns:
            Cosine similarity score (0-1)
        """
        vec1 = np.array(embedding1.embedding)
        vec2 = np.array(embedding2.embedding)

        # Calculate cosine similarity
        dot_product = np.dot(vec1, vec2)
        magnitude1 = np.linalg.norm(vec1)
        magnitude2 = np.linalg.norm(vec2)

        if magnitude1 == 0 or magnitude2 == 0:
            return 0.0

        return dot_product / (magnitude1 * magnitude2)

    def find_similar_code(
        self,
        target_code: str,
        code_snippets: List[str],
        language: str = "python",
        threshold: float = 0.8,
    ) -> List[Tuple[str, float]]:
        """Find similar code snippets using optimized batch processing.

        Args:
            target_code: Code to find similarities for
            code_snippets: List of code snippets to search
            language: Programming language
            threshold: Similarity threshold

        Returns:
            List of (code, similarity_score) tuples sorted by similarity
        """
        if not code_snippets:
            return []
            
        try:
            # Generate target embedding once
            target_embedding = self.generate_embedding(target_code, language)
            target_vector = np.array(target_embedding.embedding)
            
            # Batch process snippets for better performance
            batch_size = 50  # Process in batches to manage memory
            similar_codes = []
            
            for i in range(0, len(code_snippets), batch_size):
                batch = code_snippets[i:i + batch_size]
                batch_embeddings = []
                
                # Generate embeddings for batch
                for snippet in batch:
                    try:
                        embedding = self.generate_embedding(snippet, language)
                        batch_embeddings.append((snippet, np.array(embedding.embedding)))
                    except Exception as e:
                        logger.debug(f"Failed to generate embedding for snippet: {e}")
                        continue
                
                # Calculate similarities for batch
                for snippet, snippet_vector in batch_embeddings:
                    try:
                        similarity_score = self._cosine_similarity_vectors(target_vector, snippet_vector)
                        
                        if similarity_score >= threshold:
                            similar_codes.append((snippet, similarity_score))
                    except Exception as e:
                        logger.debug(f"Failed to calculate similarity: {e}")
                        continue
            
            # Sort by similarity score (descending) and limit results
            similar_codes.sort(key=lambda x: x[1], reverse=True)
            
            # Limit to top 20 results to prevent excessive memory usage
            return similar_codes[:20]
            
        except Exception as e:
            logger.error(f"Error in find_similar_code: {e}")
            return []

    def _cosine_similarity_vectors(self, vec1: np.ndarray, vec2: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors efficiently.
        
        Args:
            vec1: First vector
            vec2: Second vector
            
        Returns:
            Cosine similarity score
        """
        try:
            # Handle zero vectors
            norm1 = np.linalg.norm(vec1)
            norm2 = np.linalg.norm(vec2)
            
            if norm1 == 0.0 or norm2 == 0.0:
                return 0.0
            
            return np.dot(vec1, vec2) / (norm1 * norm2)
        except Exception:
            return 0.0

    def analyze_code_patterns(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Analyze code patterns using embeddings and pattern recognition.

        Args:
            code: Source code to analyze
            language: Programming language

        Returns:
            Dictionary with comprehensive pattern analysis results
        """
        try:
            # Generate embedding for semantic analysis
            embedding = self.generate_embedding(code, language)
            embedding_vector = np.array(embedding.embedding)
            
            # Basic structural analysis
            structural_analysis = {
                "complexity_score": self._estimate_complexity(code),
                "security_risk_score": self._estimate_security_risk(code),
                "maintainability_score": self._estimate_maintainability(code),
                "code_quality_score": self._estimate_code_quality(code),
            }
            
            # Embedding-based analysis
            semantic_analysis = {
                "embedding_magnitude": float(np.linalg.norm(embedding_vector)),
                "embedding_entropy": self._calculate_embedding_entropy(embedding_vector),
                "semantic_complexity": self._calculate_semantic_complexity(embedding_vector),
                "pattern_diversity": self._calculate_pattern_diversity(embedding_vector),
            }
            
            # Code structure patterns
            structure_patterns = self._analyze_code_structure(code, language)
            
            # Security-specific patterns
            security_patterns = self._analyze_security_patterns(code, language, embedding_vector)
            
            # Combine all analyses
            analysis = {
                **structural_analysis,
                **semantic_analysis,
                "structure_patterns": structure_patterns,
                "security_patterns": security_patterns,
                "overall_risk_score": self._calculate_overall_risk(
                    structural_analysis, semantic_analysis, security_patterns
                ),
                "analysis_metadata": {
                    "model_used": self.model_name,
                    "embedding_dimensions": len(embedding_vector),
                    "code_length": len(code),
                    "language": language,
                }
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error in analyze_code_patterns: {e}")
            return {"error": str(e), "analysis_failed": True}

    def _estimate_complexity(self, code: str) -> float:
        """Estimate code complexity (basic implementation).

        Args:
            code: Source code

        Returns:
            Complexity score (0-1)
        """
        lines = code.split("\n")
        non_empty_lines = [line for line in lines if line.strip()]

        # Basic complexity metrics
        complexity_indicators = [
            "if",
            "elif",
            "else",
            "for",
            "while",
            "try",
            "except",
            "function",
            "def",
            "class",
            "lambda",
            "with",
        ]

        indicator_count = 0
        for line in non_empty_lines:
            for indicator in complexity_indicators:
                if indicator in line.lower():
                    indicator_count += 1

        # Normalize by number of lines
        if len(non_empty_lines) == 0:
            return 0.0

        return min(indicator_count / len(non_empty_lines), 1.0)

    def _estimate_security_risk(self, code: str) -> float:
        """Estimate security risk (basic implementation).

        Args:
            code: Source code

        Returns:
            Security risk score (0-1)
        """
        # Basic security risk indicators
        risk_indicators = [
            "eval(",
            "exec(",
            "input(",
            "raw_input(",
            "pickle.loads",
            "yaml.load",
            "shell=True",
            "sql",
            "query",
            "password",
            "secret",
            "innerHTML",
            "document.write",
        ]

        risk_count = 0
        for indicator in risk_indicators:
            if indicator in code.lower():
                risk_count += 1

        # Normalize
        return min(risk_count / 10.0, 1.0)

    def _estimate_maintainability(self, code: str) -> float:
        """Estimate maintainability (basic implementation).

        Args:
            code: Source code

        Returns:
            Maintainability score (0-1)
        """
        lines = code.split("\n")
        non_empty_lines = [line for line in lines if line.strip()]

        if len(non_empty_lines) == 0:
            return 1.0

        # Good maintainability indicators
        good_indicators = [
            "def ",
            "class ",
            "import ",
            "from ",
            '"""',
            "'''",
            "#",
            "return",
            "raise",
        ]

        good_count = 0
        for line in non_empty_lines:
            for indicator in good_indicators:
                if indicator in line:
                    good_count += 1
                    break

        # Calculate ratio
        return good_count / len(non_empty_lines)

    def _estimate_code_quality(self, code: str) -> float:
        """Estimate code quality based on multiple factors.
        
        Args:
            code: Source code
            
        Returns:
            Code quality score (0-1)
        """
        lines = code.split("\n")
        non_empty_lines = [line for line in lines if line.strip()]
        
        if len(non_empty_lines) == 0:
            return 1.0
        
        quality_score = 0.0
        
        # Check for documentation
        doc_lines = [line for line in lines if '"""' in line or "'''" in line or line.strip().startswith('#')]
        doc_ratio = len(doc_lines) / len(non_empty_lines)
        quality_score += min(doc_ratio * 2, 0.3)  # Up to 30% for documentation
        
        # Check for proper naming (basic heuristic)
        proper_naming = sum(1 for line in non_empty_lines 
                          if any(pattern in line.lower() for pattern in ['def ', 'class ', 'import ']))
        naming_ratio = proper_naming / len(non_empty_lines)
        quality_score += min(naming_ratio * 3, 0.2)  # Up to 20% for structure
        
        # Check for error handling
        error_handling = sum(1 for line in non_empty_lines 
                           if any(pattern in line.lower() for pattern in ['try:', 'except', 'finally:', 'raise']))
        error_ratio = error_handling / len(non_empty_lines)
        quality_score += min(error_ratio * 5, 0.2)  # Up to 20% for error handling
        
        # Penalize very long lines
        long_lines = sum(1 for line in non_empty_lines if len(line) > 120)
        long_line_penalty = (long_lines / len(non_empty_lines)) * 0.2
        quality_score -= long_line_penalty
        
        # Base quality for having any code
        quality_score += 0.3
        
        return max(0.0, min(1.0, quality_score))

    def _calculate_embedding_entropy(self, embedding_vector: np.ndarray) -> float:
        """Calculate entropy of the embedding vector.
        
        Args:
            embedding_vector: Embedding vector
            
        Returns:
            Entropy value
        """
        try:
            # Normalize vector to create probability distribution
            abs_vector = np.abs(embedding_vector)
            if np.sum(abs_vector) == 0:
                return 0.0
            
            prob_dist = abs_vector / np.sum(abs_vector)
            
            # Calculate entropy
            entropy = -np.sum(prob_dist * np.log2(prob_dist + 1e-10))
            
            # Normalize by maximum possible entropy
            max_entropy = np.log2(len(embedding_vector))
            normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0.0
            
            return float(normalized_entropy)
        except Exception:
            return 0.0

    def _calculate_semantic_complexity(self, embedding_vector: np.ndarray) -> float:
        """Calculate semantic complexity based on embedding characteristics.
        
        Args:
            embedding_vector: Embedding vector
            
        Returns:
            Semantic complexity score (0-1)
        """
        try:
            # Calculate variance as a measure of complexity
            variance = float(np.var(embedding_vector))
            
            # Calculate range of values
            value_range = float(np.max(embedding_vector) - np.min(embedding_vector))
            
            # Calculate sparsity (how many dimensions are near zero)
            sparsity = float(np.sum(np.abs(embedding_vector) < 0.01) / len(embedding_vector))
            
            # Combine metrics (higher variance and range, lower sparsity = higher complexity)
            complexity = (variance * 0.4 + value_range * 0.4 + (1 - sparsity) * 0.2)
            
            # Normalize to 0-1 range (approximate)
            return min(1.0, max(0.0, complexity / 2.0))
        except Exception:
            return 0.5

    def _calculate_pattern_diversity(self, embedding_vector: np.ndarray) -> float:
        """Calculate pattern diversity in the embedding.
        
        Args:
            embedding_vector: Embedding vector
            
        Returns:
            Pattern diversity score (0-1)
        """
        try:
            # Split vector into chunks and analyze diversity
            chunk_size = max(1, len(embedding_vector) // 8)
            chunks = [embedding_vector[i:i+chunk_size] 
                     for i in range(0, len(embedding_vector), chunk_size)]
            
            if len(chunks) < 2:
                return 0.5
            
            # Calculate pairwise cosine similarities between chunks
            similarities = []
            for i in range(len(chunks)):
                for j in range(i+1, len(chunks)):
                    sim = self._cosine_similarity_vectors(chunks[i], chunks[j])
                    similarities.append(sim)
            
            if not similarities:
                return 0.5
            
            # Diversity is inverse of average similarity
            avg_similarity = np.mean(similarities)
            diversity = 1.0 - avg_similarity
            
            return float(max(0.0, min(1.0, diversity)))
        except Exception:
            return 0.5

    def _analyze_code_structure(self, code: str, language: str) -> Dict[str, Any]:
        """Analyze code structure patterns.
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            Structure analysis results
        """
        lines = code.split("\n")
        non_empty_lines = [line for line in lines if line.strip()]
        
        structure = {
            "total_lines": len(lines),
            "code_lines": len(non_empty_lines),
            "comment_lines": sum(1 for line in lines if line.strip().startswith('#')),
            "blank_lines": len(lines) - len(non_empty_lines),
            "indentation_levels": self._analyze_indentation(lines),
            "function_count": self._count_functions(code, language),
            "class_count": self._count_classes(code, language),
            "import_count": self._count_imports(code, language),
            "control_structures": self._count_control_structures(code, language),
        }
        
        # Calculate ratios
        if structure["total_lines"] > 0:
            structure["comment_ratio"] = structure["comment_lines"] / structure["total_lines"]
            structure["code_density"] = structure["code_lines"] / structure["total_lines"]
        else:
            structure["comment_ratio"] = 0.0
            structure["code_density"] = 0.0
        
        return structure

    def _analyze_security_patterns(self, code: str, language: str, embedding_vector: np.ndarray) -> Dict[str, Any]:
        """Analyze security-related patterns.
        
        Args:
            code: Source code
            language: Programming language
            embedding_vector: Code embedding vector
            
        Returns:
            Security pattern analysis
        """
        # Enhanced security pattern detection
        security_indicators = {
            "python": [
                "eval(", "exec(", "input(", "raw_input(", "pickle.loads", "yaml.load",
                "shell=True", "sql", "query", "password", "secret", "api_key", "token",
                "subprocess", "os.system", "os.popen", "__import__", "compile("
            ],
            "javascript": [
                "eval(", "innerHTML", "document.write", "setTimeout(", "setInterval(",
                "new Function(", "localStorage", "sessionStorage", "cookie", "btoa", "atob",
                "XMLHttpRequest", "fetch(", "postMessage", "window.open"
            ],
            "java": [
                "Runtime.exec", "ProcessBuilder", "Class.forName", "Method.invoke",
                "URLClassLoader", "ScriptEngine", "Expression", "Statement.execute"
            ]
        }
        
        patterns = security_indicators.get(language, security_indicators["python"])
        
        detected_patterns = []
        risk_score = 0.0
        
        code_lower = code.lower()
        for pattern in patterns:
            if pattern.lower() in code_lower:
                detected_patterns.append(pattern)
                # Different patterns have different risk weights
                if pattern in ["eval(", "exec(", "os.system"]:
                    risk_score += 0.3
                elif pattern in ["subprocess", "Runtime.exec", "innerHTML"]:
                    risk_score += 0.2
                else:
                    risk_score += 0.1
        
        # Analyze embedding for potential security concerns
        embedding_risk = self._analyze_embedding_security_signals(embedding_vector)
        
        return {
            "detected_patterns": detected_patterns,
            "pattern_count": len(detected_patterns),
            "risk_score": min(1.0, risk_score),
            "embedding_security_score": embedding_risk,
            "high_risk_patterns": [p for p in detected_patterns 
                                 if p in ["eval(", "exec(", "os.system", "Runtime.exec"]],
            "medium_risk_patterns": [p for p in detected_patterns 
                                   if p in ["subprocess", "innerHTML", "document.write"]],
        }

    def _calculate_overall_risk(self, structural: Dict, semantic: Dict, security: Dict) -> float:
        """Calculate overall risk score combining all analyses.
        
        Args:
            structural: Structural analysis results
            semantic: Semantic analysis results  
            security: Security analysis results
            
        Returns:
            Overall risk score (0-1)
        """
        try:
            # Weight different risk factors
            structure_risk = (
                structural.get("complexity_score", 0) * 0.3 +
                (1 - structural.get("maintainability_score", 1)) * 0.2 +
                (1 - structural.get("code_quality_score", 1)) * 0.2
            )
            
            semantic_risk = (
                semantic.get("semantic_complexity", 0) * 0.4 +
                min(semantic.get("embedding_entropy", 0), 0.5) * 0.3
            )
            
            security_risk = security.get("risk_score", 0) * 0.8 + security.get("embedding_security_score", 0) * 0.2
            
            # Combine with weights: security most important, then structure, then semantic
            overall_risk = (
                security_risk * 0.5 +
                structure_risk * 0.3 +
                semantic_risk * 0.2
            )
            
            return float(max(0.0, min(1.0, overall_risk)))
        except Exception:
            return 0.5

    def _analyze_indentation(self, lines: List[str]) -> Dict[str, int]:
        """Analyze indentation patterns."""
        indentation_levels = {}
        for line in lines:
            if line.strip():
                leading_spaces = len(line) - len(line.lstrip())
                level = leading_spaces // 4  # Assume 4-space indentation
                indentation_levels[level] = indentation_levels.get(level, 0) + 1
        return indentation_levels

    def _count_functions(self, code: str, language: str) -> int:
        """Count function definitions."""
        if language == "python":
            return code.count("def ")
        elif language in ["javascript", "typescript"]:
            return code.count("function ") + code.count("=> ")
        elif language == "java":
            return len([line for line in code.split("\n") 
                       if "public" in line and "(" in line and "{" in line])
        return 0

    def _count_classes(self, code: str, language: str) -> int:
        """Count class definitions."""
        if language in ["python", "java"]:
            return code.count("class ")
        elif language in ["javascript", "typescript"]:
            return code.count("class ")
        return 0

    def _count_imports(self, code: str, language: str) -> int:
        """Count import statements."""
        if language == "python":
            return code.count("import ") + code.count("from ")
        elif language in ["javascript", "typescript"]:
            return code.count("import ") + code.count("require(")
        elif language == "java":
            return code.count("import ")
        return 0

    def _count_control_structures(self, code: str, language: str) -> Dict[str, int]:
        """Count control structure usage."""
        structures = {
            "if_statements": code.count("if "),
            "for_loops": code.count("for "),
            "while_loops": code.count("while "),
            "try_blocks": code.count("try"),
        }
        
        if language == "python":
            structures["with_statements"] = code.count("with ")
            structures["async_functions"] = code.count("async def")
        
        return structures

    def _analyze_embedding_security_signals(self, embedding_vector: np.ndarray) -> float:
        """Analyze embedding for security-related signals.
        
        This is a placeholder for more sophisticated analysis that would
        require trained models to detect security patterns in embeddings.
        
        Args:
            embedding_vector: Code embedding vector
            
        Returns:
            Security risk score from embedding analysis (0-1)
        """
        try:
            # Simple heuristic: high magnitude values might indicate complex/risky code
            max_magnitude = float(np.max(np.abs(embedding_vector)))
            mean_magnitude = float(np.mean(np.abs(embedding_vector)))
            
            # High variance might indicate complex control flow
            variance = float(np.var(embedding_vector))
            
            # Combine signals (this is a basic heuristic)
            risk_signal = min(1.0, (max_magnitude * 0.3 + mean_magnitude * 0.3 + variance * 0.4) / 3.0)
            
            return risk_signal
        except Exception:
            return 0.0

    def clear_cache(self) -> None:
        """Clear embedding cache."""
        self.embedding_cache.clear()
        logger.info("Embedding cache cleared")

    @classmethod
    def cleanup_model_registry(cls) -> None:
        """Clean up all models in the registry."""
        if cls._model_registry:
            cls._model_registry.cleanup_all()
            logger.info("Cleaned up model registry")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        cache_size = len(self.embedding_cache)
        return {
            "cache_size": cache_size,
            "cache_limit": self.cache_size_limit,
            "cache_usage_percent": int((cache_size / self.cache_size_limit) * 100) if self.cache_size_limit > 0 else 0,
            "model_loaded": self._model_loaded,
            "device": str(self.device),
        }
