# ═══════════════════════════════════════════════════════════════
# RAGLOX v3.0 - DeepSeek Provider
# LLM provider for DeepSeek API with reasoning capabilities
# ═══════════════════════════════════════════════════════════════

"""
DeepSeek Provider - Enterprise AI Integration

This provider extends OpenAI provider with DeepSeek-specific features:
1. Reasoning mode (DeepSeek-R1) - shows chain of thought
2. Chat mode (DeepSeek-V3) - fast, efficient responses
3. Function calling support for tool integration
4. Streaming support for real-time responses

Models:
- deepseek-reasoner: For complex reasoning tasks (penetration testing, planning)
- deepseek-chat: For fast conversational responses
"""

import json
import time
from typing import Any, Dict, List, Optional

from .openai_provider import OpenAIProvider
from .base import (
    LLMConfig,
    LLMMessage,
    LLMResponse,
    TokenUsage,
)


class ReasoningResponse:
    """
    Enhanced response with reasoning content.
    
    DeepSeek-R1 returns reasoning process before the final answer.
    This class captures both the reasoning and the final content.
    """
    
    def __init__(
        self,
        content: str,
        reasoning: Optional[str] = None,
        usage: Optional[TokenUsage] = None,
        model: str = "deepseek-reasoner",
        latency_ms: float = 0.0,
        raw_response: Optional[Dict[str, Any]] = None,
    ):
        self.content = content
        self.reasoning = reasoning  # Chain of thought process
        self.usage = usage
        self.model = model
        self.latency_ms = latency_ms
        self.raw_response = raw_response
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content": self.content,
            "reasoning": self.reasoning,
            "usage": self.usage.to_dict() if self.usage else None,
            "model": self.model,
            "latency_ms": self.latency_ms,
        }


class DeepSeekProvider(OpenAIProvider):
    """
    DeepSeek API provider - Enterprise AI with reasoning capabilities.
    
    Architecture:
    - Extends OpenAIProvider for SDK compatibility
    - Uses DeepSeek API endpoint (https://api.deepseek.com)
    - Supports both reasoning (R1) and chat (V3) modes
    - Function calling for tool integration
    - Streaming for real-time responses
    
    Usage:
        config = LLMConfig(
            provider="deepseek",
            api_key="sk-...",
            model="deepseek-reasoner"  # or "deepseek-chat"
        )
        provider = DeepSeekProvider(config)
        
        # Generate with reasoning
        response = await provider.generate_with_reasoning(
            messages=[{"role": "user", "content": "Analyze this target..."}]
        )
        print(response.reasoning)  # Shows thought process
        print(response.content)    # Final answer
    """
    
    DEEPSEEK_BASE_URL = "https://api.deepseek.com"
    
    AVAILABLE_MODELS = [
        "deepseek-reasoner",  # DeepSeek-R1: Shows reasoning process
        "deepseek-chat",      # DeepSeek-V3: Fast chat responses
    ]
    
    def __init__(self, config: LLMConfig):
        """
        Initialize DeepSeek provider.
        
        Args:
            config: LLM configuration with DeepSeek API key
                   Set api_base to use custom endpoint
        """
        # Force base_url to DeepSeek API if not specified
        if not config.api_base:
            config.api_base = self.DEEPSEEK_BASE_URL
        
        # Initialize parent OpenAI provider
        super().__init__(config)
        
        # Override default model if not set
        if not config.model or config.model.startswith("gpt-"):
            self.config.model = "deepseek-reasoner"
        
        self.logger.info(f"🧠 DeepSeek Provider initialized with model: {self.config.model}")
    
    @property
    def provider_name(self) -> str:
        return "deepseek"
    
    @property
    def available_models(self) -> List[str]:
        return self.AVAILABLE_MODELS.copy()
    
    async def generate_with_reasoning(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> ReasoningResponse:
        """
        Generate response with reasoning process (DeepSeek-R1 mode).
        
        This method extracts the reasoning content from DeepSeek's response,
        which shows the chain of thought before the final answer.
        
        Args:
            messages: List of conversation messages
            **kwargs: Additional parameters (temperature, max_tokens, etc.)
        
        Returns:
            ReasoningResponse with both reasoning and final content
        
        Example:
            >>> messages = [
            ...     LLMMessage(role="user", content="How do I scan port 22?")
            ... ]
            >>> response = await provider.generate_with_reasoning(messages)
            >>> print(response.reasoning)
            "Let me think about this...
            1. Port 22 is SSH service
            2. Best tool is nmap
            3. Should check if target is reachable first..."
            >>> print(response.content)
            "Use: nmap -p 22 -sV <target_ip>"
        """
        # Force model to reasoner if not specified
        if "model" not in kwargs:
            kwargs["model"] = "deepseek-reasoner"
        
        # Generate using parent method
        start_time = time.time()
        llm_response = await self.generate(messages, **kwargs)
        latency_ms = (time.time() - start_time) * 1000
        
        # Extract reasoning from response
        reasoning = self._extract_reasoning(llm_response)
        
        # Create enhanced response
        return ReasoningResponse(
            content=llm_response.content,
            reasoning=reasoning,
            usage=llm_response.usage,
            model=llm_response.model,
            latency_ms=latency_ms,
            raw_response=llm_response.raw_response,
        )
    
    async def generate_fast(
        self,
        messages: List[LLMMessage],
        **kwargs
    ) -> LLMResponse:
        """
        Generate fast response without reasoning (DeepSeek-V3 chat mode).
        
        Use this for:
        - Simple questions
        - Status updates
        - Fast conversational responses
        
        Args:
            messages: List of conversation messages
            **kwargs: Additional parameters
        
        Returns:
            Standard LLM response
        """
        # Force model to chat
        kwargs["model"] = "deepseek-chat"
        
        return await self.generate(messages, **kwargs)
    
    async def generate_with_tools(
        self,
        messages: List[LLMMessage],
        tools: List[Dict[str, Any]],
        tool_choice: str = "auto",
        **kwargs
    ) -> LLMResponse:
        """
        Generate response with tool/function calling support.
        
        This enables the agent to call available tools (shell commands,
        network scans, exploits) based on the conversation context.
        
        Args:
            messages: Conversation history
            tools: List of available tools (OpenAI function format)
            tool_choice: "auto", "none", or specific tool name
            **kwargs: Additional parameters
        
        Returns:
            LLM response with potential tool_calls
        
        Example:
            >>> tools = [
            ...     {
            ...         "type": "function",
            ...         "function": {
            ...             "name": "run_nmap",
            ...             "description": "Scan ports with nmap",
            ...             "parameters": {
            ...                 "type": "object",
            ...                 "properties": {
            ...                     "target": {"type": "string"},
            ...                     "ports": {"type": "string"},
            ...                 },
            ...                 "required": ["target"]
            ...             }
            ...         }
            ...     }
            ... ]
            >>> response = await provider.generate_with_tools(
            ...     messages=[...],
            ...     tools=tools
            ... )
            >>> if response.raw_response.get("tool_calls"):
            ...     # Execute the requested tool
            ...     tool_call = response.raw_response["tool_calls"][0]
            ...     function_name = tool_call["function"]["name"]
            ...     args = json.loads(tool_call["function"]["arguments"])
        """
        # Add tools to request
        kwargs["tools"] = tools
        kwargs["tool_choice"] = tool_choice
        
        return await self.generate(messages, **kwargs)
    
    def _extract_reasoning(self, response: LLMResponse) -> Optional[str]:
        """
        Extract reasoning content from DeepSeek response.
        
        DeepSeek-R1 includes reasoning in the response. This can be:
        1. In a separate 'reasoning_content' field (if API supports it)
        2. Within the content before a marker like "---" or "Answer:"
        3. As structured JSON with reasoning key
        
        Args:
            response: Standard LLM response
        
        Returns:
            Extracted reasoning text or None
        """
        # Method 1: Check if API returns reasoning_content directly
        if response.raw_response:
            # Check message for reasoning_content
            choices = response.raw_response.get("choices", [])
            if choices:
                message = choices[0].get("message", {})
                reasoning_content = message.get("reasoning_content")
                if reasoning_content:
                    return reasoning_content
        
        # Method 2: Parse content for reasoning markers
        content = response.content
        if not content:
            return None
        
        # Try to split on common markers
        markers = [
            "\n---\n",
            "\nAnswer:\n",
            "\nFinal Answer:\n",
            "\nConclusion:\n",
            "\n##\n",
        ]
        
        for marker in markers:
            if marker in content:
                parts = content.split(marker, 1)
                if len(parts) == 2:
                    # First part is reasoning, second is answer
                    return parts[0].strip()
        
        # Method 3: Try to parse as JSON
        if content.strip().startswith("{"):
            try:
                data = json.loads(content)
                if "reasoning" in data:
                    return data["reasoning"]
                if "thought_process" in data:
                    return data["thought_process"]
                if "chain_of_thought" in data:
                    return data["chain_of_thought"]
            except json.JSONDecodeError:
                pass
        
        # No reasoning found - return None
        # (The full content is already in response.content)
        return None
    
    def supports_reasoning(self, model: Optional[str] = None) -> bool:
        """
        Check if model supports reasoning mode.
        
        Args:
            model: Model name (uses config.model if not specified)
        
        Returns:
            True if model supports reasoning
        """
        model = model or self.config.model
        return "reasoner" in model.lower() or "r1" in model.lower()
    
    def supports_streaming(self) -> bool:
        """
        Check if provider supports streaming responses.
        
        Returns:
            True (DeepSeek supports streaming)
        """
        return True
    
    async def health_check(self) -> bool:
        """
        Check if DeepSeek API is accessible.
        
        Returns:
            True if API is healthy
        """
        try:
            # Try a simple request
            messages = [LLMMessage(role="user", content="ping")]
            response = await self.generate_fast(
                messages=messages,
                max_tokens=10
            )
            return bool(response.content)
        except Exception as e:
            self.logger.warning(f"DeepSeek health check failed: {e}")
            return False


# ═══════════════════════════════════════════════════════════════
# Factory Function
# ═══════════════════════════════════════════════════════════════

def create_deepseek_provider(
    api_key: str,
    model: str = "deepseek-reasoner",
    temperature: float = 0.7,
    max_tokens: int = 8000,
    **kwargs
) -> DeepSeekProvider:
    """
    Factory function to create DeepSeek provider with common defaults.
    
    Args:
        api_key: DeepSeek API key
        model: Model to use (default: deepseek-reasoner)
        temperature: Sampling temperature (default: 0.7)
        max_tokens: Maximum tokens (default: 8000)
        **kwargs: Additional config parameters
    
    Returns:
        Configured DeepSeekProvider
    
    Example:
        >>> provider = create_deepseek_provider(
        ...     api_key="sk-...",
        ...     model="deepseek-reasoner",
        ...     temperature=0.3  # Lower for more deterministic
        ... )
    """
    config = LLMConfig(
        provider="deepseek",
        api_key=api_key,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        **kwargs
    )
    
    return DeepSeekProvider(config)
