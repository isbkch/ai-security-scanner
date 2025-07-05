"""Language detection utilities."""

import os
from pathlib import Path
from typing import Optional, Dict, List
import logging

logger = logging.getLogger(__name__)


class LanguageDetector:
    """Utility class for detecting programming languages from file paths."""
    
    def __init__(self):
        """Initialize language detector with file extension mappings."""
        self.extension_map = {
            # Python
            '.py': 'python',
            '.pyx': 'python',
            '.pyi': 'python',
            '.pyw': 'python',
            
            # JavaScript/TypeScript
            '.js': 'javascript',
            '.jsx': 'javascript',
            '.mjs': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            
            # Java
            '.java': 'java',
            '.class': 'java',
            '.jar': 'java',
            
            # C/C++
            '.c': 'c',
            '.h': 'c',
            '.cpp': 'cpp',
            '.cxx': 'cpp',
            '.cc': 'cpp',
            '.hpp': 'cpp',
            '.hxx': 'cpp',
            
            # C#
            '.cs': 'csharp',
            '.csx': 'csharp',
            
            # Go
            '.go': 'go',
            
            # Rust
            '.rs': 'rust',
            
            # PHP
            '.php': 'php',
            '.php3': 'php',
            '.php4': 'php',
            '.php5': 'php',
            '.phtml': 'php',
            
            # Ruby
            '.rb': 'ruby',
            '.rbw': 'ruby',
            
            # Swift
            '.swift': 'swift',
            
            # Kotlin
            '.kt': 'kotlin',
            '.kts': 'kotlin',
            
            # Scala
            '.scala': 'scala',
            '.sc': 'scala',
            
            # Shell
            '.sh': 'shell',
            '.bash': 'shell',
            '.zsh': 'shell',
            '.fish': 'shell',
            
            # SQL
            '.sql': 'sql',
            
            # HTML/XML
            '.html': 'html',
            '.htm': 'html',
            '.xml': 'xml',
            '.xhtml': 'html',
            
            # CSS
            '.css': 'css',
            '.scss': 'css',
            '.sass': 'css',
            '.less': 'css',
            
            # Configuration files
            '.json': 'json',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.toml': 'toml',
            '.ini': 'ini',
            '.cfg': 'ini',
            '.conf': 'ini',
            
            # Dockerfile
            '.dockerfile': 'dockerfile',
            
            # Markdown
            '.md': 'markdown',
            '.markdown': 'markdown',
        }
        
        # Special filename patterns
        self.filename_map = {
            'dockerfile': 'dockerfile',
            'makefile': 'makefile',
            'cmake': 'cmake',
            'cmakelists.txt': 'cmake',
            'requirements.txt': 'requirements',
            'package.json': 'json',
            'package-lock.json': 'json',
            'yarn.lock': 'yaml',
            'pipfile': 'toml',
            'pipfile.lock': 'json',
            'setup.py': 'python',
            'setup.cfg': 'ini',
            'pyproject.toml': 'toml',
            'tox.ini': 'ini',
            '.gitignore': 'gitignore',
            '.gitattributes': 'gitattributes',
            '.env': 'env',
            '.env.example': 'env',
            '.env.local': 'env',
            '.env.development': 'env',
            '.env.production': 'env',
            '.env.test': 'env',
        }
        
        # Language aliases for compatibility
        self.language_aliases = {
            'typescript': 'javascript',  # TypeScript analysis can use JavaScript patterns
            'jsx': 'javascript',
            'tsx': 'javascript',
        }
    
    def detect_language(self, file_path: str) -> Optional[str]:
        """Detect programming language from file path.
        
        Args:
            file_path: Path to file
            
        Returns:
            Detected language or None if not detected
        """
        path_obj = Path(file_path)
        
        # Check filename patterns first
        filename_lower = path_obj.name.lower()
        if filename_lower in self.filename_map:
            language = self.filename_map[filename_lower]
            return self._resolve_language_alias(language)
        
        # Check file extension
        extension = path_obj.suffix.lower()
        if extension in self.extension_map:
            language = self.extension_map[extension]
            return self._resolve_language_alias(language)
        
        # Check for shebang line in files without extensions
        if not extension:
            shebang_language = self._detect_from_shebang(file_path)
            if shebang_language:
                return self._resolve_language_alias(shebang_language)
        
        return None
    
    def _resolve_language_alias(self, language: str) -> str:
        """Resolve language aliases.
        
        Args:
            language: Language name
            
        Returns:
            Resolved language name
        """
        return self.language_aliases.get(language, language)
    
    def _detect_from_shebang(self, file_path: str) -> Optional[str]:
        """Detect language from shebang line.
        
        Args:
            file_path: Path to file
            
        Returns:
            Detected language or None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                
                if first_line.startswith('#!'):
                    # Extract interpreter from shebang
                    shebang = first_line[2:].strip()
                    
                    # Common interpreters
                    if 'python' in shebang:
                        return 'python'
                    elif 'node' in shebang:
                        return 'javascript'
                    elif 'bash' in shebang or 'sh' in shebang:
                        return 'shell'
                    elif 'ruby' in shebang:
                        return 'ruby'
                    elif 'perl' in shebang:
                        return 'perl'
                    elif 'php' in shebang:
                        return 'php'
                    
        except Exception as e:
            logger.debug(f"Error reading shebang from {file_path}: {e}")
        
        return None
    
    def get_supported_languages(self) -> List[str]:
        """Get list of all supported languages.
        
        Returns:
            List of supported language names
        """
        languages = set(self.extension_map.values())
        languages.update(self.filename_map.values())
        return sorted(languages)
    
    def get_extensions_for_language(self, language: str) -> List[str]:
        """Get file extensions for a specific language.
        
        Args:
            language: Language name
            
        Returns:
            List of file extensions for the language
        """
        # Resolve alias
        resolved_language = self._resolve_language_alias(language)
        
        extensions = []
        for ext, lang in self.extension_map.items():
            if self._resolve_language_alias(lang) == resolved_language:
                extensions.append(ext)
        
        return extensions
    
    def is_supported_language(self, language: str) -> bool:
        """Check if language is supported.
        
        Args:
            language: Language name
            
        Returns:
            True if language is supported
        """
        return language in self.get_supported_languages()
    
    def detect_project_languages(self, directory_path: str) -> Dict[str, int]:
        """Detect all languages used in a project directory.
        
        Args:
            directory_path: Path to project directory
            
        Returns:
            Dictionary mapping language names to file counts
        """
        directory = Path(directory_path)
        if not directory.exists() or not directory.is_dir():
            return {}
        
        language_counts = {}
        
        # Walk through directory tree
        for root, dirs, files in os.walk(directory):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                file_path = Path(root) / file
                language = self.detect_language(str(file_path))
                
                if language:
                    language_counts[language] = language_counts.get(language, 0) + 1
        
        return language_counts
    
    def get_primary_language(self, directory_path: str) -> Optional[str]:
        """Get the primary language of a project.
        
        Args:
            directory_path: Path to project directory
            
        Returns:
            Primary language name or None
        """
        language_counts = self.detect_project_languages(directory_path)
        
        if not language_counts:
            return None
        
        # Return language with most files
        return max(language_counts.items(), key=lambda x: x[1])[0]