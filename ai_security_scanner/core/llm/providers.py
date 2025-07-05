"""LLM providers for vulnerability analysis."""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
import time

from ai_security_scanner.core.config import Config

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""
    
    def __init__(self, config: Config):
        """Initialize LLM provider.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.last_request_time = 0
        self.request_count = 0
        self.rate_limit_delay = 60.0 / config.llm.rate_limit_requests_per_minute
    
    @abstractmethod
    async def analyze_vulnerability(
        self,
        code: str,
        vulnerability_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze vulnerability and provide explanation.
        
        Args:
            code: Source code snippet
            vulnerability_type: Type of vulnerability
            context: Additional context information
            
        Returns:
            Analysis result dictionary
        """
        pass
    
    @abstractmethod
    async def check_false_positive(
        self,
        code: str,
        vulnerability_description: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check if vulnerability is a false positive.
        
        Args:
            code: Source code snippet
            vulnerability_description: Description of the vulnerability
            context: Additional context information
            
        Returns:
            False positive analysis result
        """
        pass
    
    def _enforce_rate_limit(self) -> None:
        """Enforce rate limiting."""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last_request
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def _create_system_prompt(self) -> str:
        """Create system prompt for vulnerability analysis."""
        return """You are a cybersecurity expert specializing in code analysis and vulnerability detection.

Your role is to:
1. Analyze code snippets for security vulnerabilities
2. Provide clear, actionable explanations of security issues
3. Suggest specific remediation steps
4. Assess whether detected issues are false positives
5. Consider the context and real-world impact of vulnerabilities

Guidelines:
- Be precise and technical in your analysis
- Focus on actionable security advice
- Consider both immediate and long-term security implications
- Explain the potential attack vectors and impact
- Provide specific code examples for remediation when possible
- Be honest about uncertainty - if you're not sure, say so

Response format should be JSON with the following structure:
{
    "analysis": "detailed analysis of the vulnerability",
    "severity_assessment": "LOW|MEDIUM|HIGH|CRITICAL",
    "false_positive_likelihood": 0.0-1.0,
    "remediation": "specific steps to fix the issue",
    "attack_vectors": ["list of potential attack vectors"],
    "impact": "description of potential impact",
    "confidence": "LOW|MEDIUM|HIGH"
}"""
    
    def _create_vulnerability_analysis_prompt(
        self,
        code: str,
        vulnerability_type: str,
        context: Dict[str, Any]
    ) -> str:
        """Create prompt for vulnerability analysis.
        
        Args:
            code: Source code snippet
            vulnerability_type: Type of vulnerability
            context: Additional context
            
        Returns:
            Analysis prompt
        """
        language = context.get('language', 'unknown')
        file_path = context.get('file_path', 'unknown')
        
        return f"""Analyze this code snippet for a potential {vulnerability_type} vulnerability:

**Code (Language: {language}):**
```{language}
{code}
```

**File Path:** {file_path}

**Context:**
{self._format_context(context)}

**Vulnerability Type:** {vulnerability_type}

Please provide a detailed analysis focusing on:
1. Whether this is actually a vulnerability
2. The severity and potential impact
3. Specific attack scenarios
4. Exact remediation steps with code examples
5. Your confidence level in this assessment

Be especially careful to avoid false positives - consider the full context and whether the code is actually exploitable."""
    
    def _create_false_positive_check_prompt(
        self,
        code: str,
        vulnerability_description: str,
        context: Dict[str, Any]
    ) -> str:
        """Create prompt for false positive checking.
        
        Args:
            code: Source code snippet
            vulnerability_description: Description of vulnerability
            context: Additional context
            
        Returns:
            False positive check prompt
        """
        language = context.get('language', 'unknown')
        
        return f"""Review this potential vulnerability detection and assess if it's a false positive:

**Code (Language: {language}):**
```{language}
{code}
```

**Vulnerability Description:** {vulnerability_description}

**Context:**
{self._format_context(context)}

Please analyze whether this is a false positive by considering:
1. Is the code actually vulnerable in a real-world scenario?
2. Are there mitigating factors that prevent exploitation?
3. Is the vulnerable code path actually reachable?
4. Are there input sanitization or validation mechanisms?
5. Is this a test file or example code?

Provide your assessment with a confidence score and detailed reasoning."""
    
    def _format_context(self, context: Dict[str, Any]) -> str:
        """Format context information for prompts.
        
        Args:
            context: Context dictionary
            
        Returns:
            Formatted context string
        """
        formatted_lines = []
        
        for key, value in context.items():
            if key in ['language', 'file_path']:
                continue  # These are handled separately
            
            if isinstance(value, (list, dict)):
                formatted_lines.append(f"- {key}: {str(value)}")
            else:
                formatted_lines.append(f"- {key}: {value}")
        
        return '\n'.join(formatted_lines) if formatted_lines else "No additional context provided"


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider for vulnerability analysis."""
    
    def __init__(self, config: Config):
        """Initialize OpenAI provider.
        
        Args:
            config: Configuration object
        """
        super().__init__(config)
        
        try:
            import openai
            self.client = openai.AsyncOpenAI(
                api_key=config.get_api_key(config.llm.api_key_env),
                base_url=config.llm.api_base_url,
                timeout=config.llm.timeout
            )
        except ImportError:
            raise ImportError("OpenAI library not installed. Run: pip install openai")
    
    async def analyze_vulnerability(
        self,
        code: str,
        vulnerability_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze vulnerability using OpenAI GPT.
        
        Args:
            code: Source code snippet
            vulnerability_type: Type of vulnerability
            context: Additional context information
            
        Returns:
            Analysis result dictionary
        """
        self._enforce_rate_limit()
        
        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_vulnerability_analysis_prompt(code, vulnerability_type, context)
            
            response = await self.client.chat.completions.create(
                model=self.config.llm.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
                response_format={"type": "json_object"}
            )
            
            result = response.choices[0].message.content
            
            # Parse JSON response
            import json
            return json.loads(result)
            
        except Exception as e:
            logger.error(f"Error in OpenAI vulnerability analysis: {e}")
            return self._create_error_response(str(e))
    
    async def check_false_positive(
        self,
        code: str,
        vulnerability_description: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check false positive using OpenAI GPT.
        
        Args:
            code: Source code snippet
            vulnerability_description: Description of vulnerability
            context: Additional context information
            
        Returns:
            False positive analysis result
        """
        self._enforce_rate_limit()
        
        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_false_positive_check_prompt(code, vulnerability_description, context)
            
            response = await self.client.chat.completions.create(
                model=self.config.llm.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=self.config.llm.temperature,
                max_tokens=self.config.llm.max_tokens,
                response_format={"type": "json_object"}
            )
            
            result = response.choices[0].message.content
            
            # Parse JSON response
            import json
            return json.loads(result)
            
        except Exception as e:
            logger.error(f"Error in OpenAI false positive check: {e}")
            return self._create_error_response(str(e))
    
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response.
        
        Args:
            error_message: Error message
            
        Returns:
            Error response dictionary
        """
        return {
            "analysis": f"Error in LLM analysis: {error_message}",
            "severity_assessment": "UNKNOWN",
            "false_positive_likelihood": 0.5,
            "remediation": "Unable to provide remediation due to analysis error",
            "attack_vectors": [],
            "impact": "Unknown due to analysis error",
            "confidence": "LOW",
            "error": error_message
        }


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider for vulnerability analysis."""
    
    def __init__(self, config: Config):
        """Initialize Anthropic provider.
        
        Args:
            config: Configuration object
        """
        super().__init__(config)
        
        try:
            import anthropic
            self.client = anthropic.AsyncAnthropic(
                api_key=config.get_api_key(config.llm.api_key_env),
                timeout=config.llm.timeout
            )
        except ImportError:
            raise ImportError("Anthropic library not installed. Run: pip install anthropic")
    
    async def analyze_vulnerability(
        self,
        code: str,
        vulnerability_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze vulnerability using Anthropic Claude.
        
        Args:
            code: Source code snippet
            vulnerability_type: Type of vulnerability
            context: Additional context information
            
        Returns:
            Analysis result dictionary
        """
        self._enforce_rate_limit()
        
        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_vulnerability_analysis_prompt(code, vulnerability_type, context)
            
            response = await self.client.messages.create(
                model=self.config.llm.model,
                max_tokens=self.config.llm.max_tokens,
                temperature=self.config.llm.temperature,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            result = response.content[0].text
            
            # Parse JSON response
            import json
            return json.loads(result)
            
        except Exception as e:
            logger.error(f"Error in Anthropic vulnerability analysis: {e}")
            return self._create_error_response(str(e))
    
    async def check_false_positive(
        self,
        code: str,
        vulnerability_description: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check false positive using Anthropic Claude.
        
        Args:
            code: Source code snippet
            vulnerability_description: Description of vulnerability
            context: Additional context information
            
        Returns:
            False positive analysis result
        """
        self._enforce_rate_limit()
        
        try:
            system_prompt = self._create_system_prompt()
            user_prompt = self._create_false_positive_check_prompt(code, vulnerability_description, context)
            
            response = await self.client.messages.create(
                model=self.config.llm.model,
                max_tokens=self.config.llm.max_tokens,
                temperature=self.config.llm.temperature,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            result = response.content[0].text
            
            # Parse JSON response
            import json
            return json.loads(result)
            
        except Exception as e:
            logger.error(f"Error in Anthropic false positive check: {e}")
            return self._create_error_response(str(e))
    
    def _create_error_response(self, error_message: str) -> Dict[str, Any]:
        """Create error response.
        
        Args:
            error_message: Error message
            
        Returns:
            Error response dictionary
        """
        return {
            "analysis": f"Error in LLM analysis: {error_message}",
            "severity_assessment": "UNKNOWN",
            "false_positive_likelihood": 0.5,
            "remediation": "Unable to provide remediation due to analysis error",
            "attack_vectors": [],
            "impact": "Unknown due to analysis error",
            "confidence": "LOW",
            "error": error_message
        }


def create_llm_provider(config: Config) -> LLMProvider:
    """Create LLM provider based on configuration.
    
    Args:
        config: Configuration object
        
    Returns:
        LLM provider instance
    """
    provider_name = config.llm.provider.lower()
    
    if provider_name == "openai":
        return OpenAIProvider(config)
    elif provider_name == "anthropic":
        return AnthropicProvider(config)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")