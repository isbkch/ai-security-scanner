"""CodeBERT embeddings for code analysis."""

import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

from ai_security_scanner.core.config import Config
from ai_security_scanner.core.models import CodeEmbedding

logger = logging.getLogger(__name__)


class CodeBERTEmbedder:
    """CodeBERT-based code embeddings generator."""
    
    # Class-level model cache to share across instances
    _model_cache = {}
    _model_lock = None

    def __init__(self, config: Optional[Config] = None):
        """Initialize CodeBERT embedder.

        Args:
            config: Configuration object
        """
        self.config = config or Config.from_env()
        self.model_name = "microsoft/codebert-base"
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Cache for embeddings
        self.embedding_cache: Dict[str, CodeEmbedding] = {}
        self.cache_size_limit = 1000

        # Initialize lock if not exists
        if CodeBERTEmbedder._model_lock is None:
            import threading
            CodeBERTEmbedder._model_lock = threading.Lock()

        # Initialize model (lazy loading with caching)
        self.tokenizer = None
        self.model = None
        self._ensure_model_loaded()

    def _ensure_model_loaded(self) -> None:
        """Ensure model is loaded with caching for performance."""
        cache_key = f"{self.model_name}:{self.device}"
        
        with CodeBERTEmbedder._model_lock:
            # Check if model is already cached
            if cache_key in CodeBERTEmbedder._model_cache:
                cached_model = CodeBERTEmbedder._model_cache[cache_key]
                self.tokenizer = cached_model["tokenizer"]
                self.model = cached_model["model"]
                logger.debug(f"Using cached CodeBERT model: {self.model_name}")
                return

            # Load model if not cached
            try:
                logger.info(f"Loading CodeBERT model: {self.model_name}")

                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                self.model = AutoModel.from_pretrained(self.model_name)

                # Move model to device
                self.model.to(self.device)
                self.model.eval()

                # Cache the loaded model
                CodeBERTEmbedder._model_cache[cache_key] = {
                    "tokenizer": self.tokenizer,
                    "model": self.model
                }

                logger.info(f"CodeBERT model loaded successfully on {self.device}")

            except Exception as e:
                logger.error(f"Error loading CodeBERT model: {e}")
                raise

    def generate_embedding(self, code: str, language: str = "python") -> CodeEmbedding:
        """Generate embedding for code snippet.

        Args:
            code: Source code to embed
            language: Programming language

        Returns:
            CodeEmbedding object
        """
        # Generate hash for caching
        code_hash = self._generate_code_hash(code)

        # Check cache
        if code_hash in self.embedding_cache:
            logger.debug(f"Using cached embedding for code hash: {code_hash}")
            return self.embedding_cache[code_hash]

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
        self._cache_embedding(code_hash, code_embedding)

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

    def _cache_embedding(self, code_hash: str, embedding: CodeEmbedding) -> None:
        """Cache embedding with size limit.

        Args:
            code_hash: Hash of the code
            embedding: Code embedding to cache
        """
        # Remove oldest entries if cache is full
        if len(self.embedding_cache) >= self.cache_size_limit:
            # Remove first entry (oldest)
            oldest_key = next(iter(self.embedding_cache))
            del self.embedding_cache[oldest_key]

        self.embedding_cache[code_hash] = embedding

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

    def clear_cache(self) -> None:
        """Clear embedding cache."""
        self.embedding_cache.clear()
        logger.info("Embedding cache cleared")

    def get_cache_stats(self) -> Dict[str, int]:
        """Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        return {
            "cache_size": len(self.embedding_cache),
            "cache_limit": self.cache_size_limit,
            "cache_usage_percent": int((len(self.embedding_cache) / self.cache_size_limit) * 100),
        }
