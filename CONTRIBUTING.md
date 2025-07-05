# Contributing to AI-Powered Code Security Scanner

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Git
- Docker (optional, for development environment)

### Local Development

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/ai-security-scanner.git
   cd ai-security-scanner
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Set Up Database**
   ```bash
   # Using Docker
   docker run -d --name ai-scanner-db -e POSTGRES_PASSWORD=password -p 5432:5432 postgres:13

   # Or install PostgreSQL locally and create database
   createdb ai_security_scanner
   ```

5. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

6. **Run Tests**
   ```bash
   pytest tests/
   ```

## Code Standards

### Python Style Guide

- Follow PEP 8
- Use type hints for all functions
- Maximum line length: 100 characters
- Use meaningful variable and function names

### Code Formatting

We use automated formatting tools:

```bash
# Format code
black ai_security_scanner/
isort ai_security_scanner/

# Lint code
flake8 ai_security_scanner/
mypy ai_security_scanner/
```

### Documentation

- All public functions must have docstrings
- Use Google-style docstrings
- Include type information in docstrings
- Add examples for complex functions

Example:
```python
def analyze_vulnerability(code: str, pattern: str) -> VulnerabilityResult:
    """Analyze code for security vulnerabilities.
    
    Args:
        code: The source code to analyze
        pattern: The vulnerability pattern to check
        
    Returns:
        VulnerabilityResult containing findings and confidence scores
        
    Raises:
        AnalysisError: If code cannot be parsed
        
    Example:
        >>> result = analyze_vulnerability("sql = f'SELECT * FROM users WHERE id={user_id}'", "sql_injection")
        >>> result.severity
        'HIGH'
    """
```

## Testing

### Test Structure

- `tests/unit/` - Unit tests for individual components
- `tests/integration/` - Integration tests for system interactions
- `tests/fixtures/` - Test data and mock objects

### Writing Tests

1. **Unit Tests**: Test individual functions/classes in isolation
2. **Integration Tests**: Test component interactions
3. **Mock External Dependencies**: Use `unittest.mock` for external APIs

Example:
```python
import pytest
from unittest.mock import Mock, patch
from ai_security_scanner.core.scanner import SecurityScanner

class TestSecurityScanner:
    def test_scan_detects_sql_injection(self):
        scanner = SecurityScanner()
        code = "query = f'SELECT * FROM users WHERE id={user_id}'"
        
        results = scanner.scan(code, language="python")
        
        assert len(results) == 1
        assert results[0].vulnerability_type == "sql_injection"
        assert results[0].severity == "HIGH"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=ai_security_scanner --cov-report=html

# Run specific test file
pytest tests/unit/test_scanner.py

# Run tests with specific markers
pytest -m "not slow"
```

## Contributing Guidelines

### Issue Reporting

1. **Search Existing Issues** before creating a new one
2. **Use Issue Templates** provided in the repository
3. **Provide Detailed Information**:
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details
   - Code samples (if applicable)

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Follow code standards
   - Add tests for new functionality
   - Update documentation

3. **Commit Changes**
   ```bash
   git commit -m "feat: add vulnerability pattern for XSS detection"
   ```

4. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **PR Requirements**:
   - Clear description of changes
   - Link to related issues
   - All tests passing
   - Code review approval

### Commit Message Format

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

Examples:
```
feat(scanner): add support for TypeScript analysis
fix(llm): handle API timeout errors gracefully
docs(readme): update installation instructions
```

## Security Considerations

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email security@your-domain.com
2. Include detailed information about the vulnerability
3. Allow time for assessment and fix before public disclosure

### Secure Coding Practices

1. **Input Validation**: Always validate user inputs
2. **Secrets Management**: Never commit API keys or passwords
3. **Error Handling**: Don't expose sensitive information in error messages
4. **Dependencies**: Keep dependencies updated and scan for vulnerabilities

## Adding New Features

### New Vulnerability Patterns

1. **Create Pattern File**
   ```python
   # ai_security_scanner/core/patterns/your_pattern.py
   from ai_security_scanner.core.patterns.base import VulnerabilityPattern
   
   class YourPattern(VulnerabilityPattern):
       def __init__(self):
           super().__init__(
               name="your_pattern",
               description="Description of the vulnerability",
               severity="HIGH",
               cwe_id="CWE-XXX"
           )
   ```

2. **Add Tests**
   ```python
   # tests/unit/patterns/test_your_pattern.py
   def test_your_pattern_detection():
       # Test implementation
   ```

3. **Update Documentation**
   - Add pattern to README.md
   - Create example in docs/examples/

### New Language Support

1. **Create Parser**
   ```python
   # ai_security_scanner/parsers/your_language/parser.py
   from ai_security_scanner.parsers.base import BaseParser
   
   class YourLanguageParser(BaseParser):
       def parse(self, code: str) -> AST:
           # Implementation
   ```

2. **Add Language Detection**
   ```python
   # ai_security_scanner/core/language_detector.py
   # Add file extension mapping
   ```

3. **Create Tests and Examples**

## Release Process

1. **Version Bump**: Update version in `pyproject.toml`
2. **Update Changelog**: Add release notes
3. **Create Release**: Tag and create GitHub release
4. **Publish Package**: Automated via GitHub Actions

## Getting Help

- **Discord**: Join our development channel
- **GitHub Discussions**: Ask questions and share ideas
- **Documentation**: Check docs/ directory
- **Code Reviews**: Request reviews from maintainers

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- GitHub releases
- Documentation acknowledgments

Thank you for contributing to making code security analysis more intelligent and accessible!