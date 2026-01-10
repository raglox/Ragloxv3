/**
 * ═══════════════════════════════════════════════════════════════
 * RAGLOX v3.0 - Reasoning Display Component
 * Shows DeepSeek's chain-of-thought reasoning process
 * ═══════════════════════════════════════════════════════════════
 * 
 * PHASE 1: DeepSeek Integration
 * 
 * This component displays the reasoning process from DeepSeek R1 model,
 * allowing users to see how the AI thinks through problems before
 * providing answers.
 */

import { useState } from 'react';
import { ChevronDown, ChevronUp, Brain, Sparkles } from 'lucide-react';

interface ReasoningDisplayProps {
  reasoning: string;
  isStreaming?: boolean;
  className?: string;
}

export function ReasoningDisplay({ 
  reasoning, 
  isStreaming = false,
  className = '' 
}: ReasoningDisplayProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  if (!reasoning || reasoning.trim().length === 0) {
    return null;
  }

  return (
    <div className={`reasoning-container border border-purple-500/30 rounded-lg overflow-hidden ${className}`}>
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between p-3 bg-purple-900/20 hover:bg-purple-900/30 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-purple-400" />
          <span className="text-sm font-medium text-purple-300">
            {isStreaming ? 'Thinking...' : 'View Reasoning Process'}
          </span>
          {isStreaming && (
            <Sparkles className="w-3 h-3 text-purple-400 animate-pulse" />
          )}
        </div>
        {isExpanded ? (
          <ChevronUp className="w-4 h-4 text-purple-400" />
        ) : (
          <ChevronDown className="w-4 h-4 text-purple-400" />
        )}
      </button>

      {/* Content */}
      {isExpanded && (
        <div className="p-4 bg-purple-950/10 backdrop-blur-sm">
          <div className="prose prose-sm prose-invert max-w-none">
            <div className="reasoning-content text-gray-300 text-sm leading-relaxed whitespace-pre-wrap">
              {reasoning}
            </div>
          </div>

          {/* Streaming indicator */}
          {isStreaming && (
            <div className="mt-3 flex items-center gap-2 text-xs text-purple-400">
              <div className="flex gap-1">
                <span className="animate-pulse delay-0">●</span>
                <span className="animate-pulse delay-75">●</span>
                <span className="animate-pulse delay-150">●</span>
              </div>
              <span>Processing...</span>
            </div>
          )}

          {/* Info footer */}
          {!isStreaming && (
            <div className="mt-3 pt-3 border-t border-purple-500/20 text-xs text-gray-500">
              💡 This shows how DeepSeek R1 reasoned through your request
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Inline reasoning display - for compact views
 */
export function InlineReasoningDisplay({ 
  reasoning,
  className = '' 
}: { reasoning: string; className?: string }) {
  if (!reasoning || reasoning.trim().length === 0) {
    return null;
  }

  return (
    <div className={`inline-reasoning text-xs text-purple-400/70 italic ${className}`}>
      💭 {reasoning.substring(0, 100)}
      {reasoning.length > 100 && '...'}
    </div>
  );
}

export default ReasoningDisplay;
