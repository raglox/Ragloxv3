/**
 * ═══════════════════════════════════════════════════════════════
 * RAGLOX v3.0 - Advanced Reasoning Steps Component
 * Step-by-step breakdown of AI reasoning process
 * ═══════════════════════════════════════════════════════════════
 * 
 * PHASE 2: Advanced Reasoning Visualization
 * 
 * This component displays DeepSeek's reasoning as individual steps,
 * showing how the AI progresses through its thought process with
 * visual indicators, timing, and confidence levels.
 */

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  CheckCircle2, 
  Circle, 
  Loader2, 
  ArrowRight,
  Brain,
  Lightbulb,
  Target,
  AlertTriangle,
  Info
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface ReasoningStep {
  id: string;
  step: number;
  title: string;
  description: string;
  status: 'pending' | 'thinking' | 'complete' | 'error';
  timestamp?: number;
  duration?: number;
  confidence?: number; // 0-100
  type?: 'analysis' | 'decision' | 'action' | 'validation';
}

interface ReasoningStepsProps {
  steps: ReasoningStep[];
  isStreaming?: boolean;
  currentStep?: number;
  className?: string;
}

export function ReasoningSteps({ 
  steps, 
  isStreaming = false,
  currentStep,
  className = '' 
}: ReasoningStepsProps) {
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  const toggleStep = (stepId: string) => {
    setExpandedSteps(prev => {
      const next = new Set(prev);
      if (next.has(stepId)) {
        next.delete(stepId);
      } else {
        next.add(stepId);
      }
      return next;
    });
  };

  const getStepIcon = (step: ReasoningStep) => {
    switch (step.status) {
      case 'complete':
        return <CheckCircle2 className="w-5 h-5 text-green-400" />;
      case 'thinking':
        return <Loader2 className="w-5 h-5 text-purple-400 animate-spin" />;
      case 'error':
        return <AlertTriangle className="w-5 h-5 text-red-400" />;
      default:
        return <Circle className="w-5 h-5 text-gray-500" />;
    }
  };

  const getStepTypeIcon = (type?: string) => {
    switch (type) {
      case 'analysis':
        return <Brain className="w-4 h-4" />;
      case 'decision':
        return <Lightbulb className="w-4 h-4" />;
      case 'action':
        return <Target className="w-4 h-4" />;
      case 'validation':
        return <Info className="w-4 h-4" />;
      default:
        return <ArrowRight className="w-4 h-4" />;
    }
  };

  const getConfidenceColor = (confidence?: number) => {
    if (!confidence) return 'bg-gray-500';
    if (confidence >= 80) return 'bg-green-500';
    if (confidence >= 60) return 'bg-yellow-500';
    if (confidence >= 40) return 'bg-orange-500';
    return 'bg-red-500';
  };

  if (!steps || steps.length === 0) {
    return null;
  }

  return (
    <div className={cn("reasoning-steps-container space-y-3", className)}>
      {/* Header */}
      <div className="flex items-center gap-2 text-sm font-medium text-purple-300 mb-3">
        <Brain className="w-4 h-4" />
        <span>Reasoning Process</span>
        {isStreaming && (
          <span className="text-xs text-purple-400 animate-pulse">
            Step {currentStep || steps.length} of analysis...
          </span>
        )}
      </div>

      {/* Steps Timeline */}
      <div className="relative">
        {/* Vertical line */}
        <div className="absolute left-[13px] top-0 bottom-0 w-[2px] bg-purple-500/20" />

        {/* Steps */}
        <AnimatePresence>
          {steps.map((step, index) => {
            const isExpanded = expandedSteps.has(step.id);
            const isActive = currentStep === step.step;

            return (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                transition={{ delay: index * 0.1 }}
                className="relative pl-10 pb-6 last:pb-0"
              >
                {/* Step indicator */}
                <div className={cn(
                  "absolute left-0 top-1 z-10 flex items-center justify-center w-7 h-7 rounded-full border-2 transition-all",
                  isActive 
                    ? "bg-purple-500 border-purple-400 shadow-lg shadow-purple-500/50" 
                    : "bg-gray-900 border-purple-500/30"
                )}>
                  {getStepIcon(step)}
                </div>

                {/* Step content */}
                <div 
                  className={cn(
                    "cursor-pointer rounded-lg border transition-all",
                    isActive 
                      ? "border-purple-500/50 bg-purple-950/30"
                      : "border-purple-500/20 bg-gray-900/30 hover:bg-gray-900/50"
                  )}
                  onClick={() => toggleStep(step.id)}
                >
                  {/* Step header */}
                  <div className="p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          {getStepTypeIcon(step.type)}
                          <span className="text-sm font-medium text-gray-200">
                            Step {step.step}: {step.title}
                          </span>
                        </div>
                        
                        {!isExpanded && (
                          <p className="text-xs text-gray-400 line-clamp-1">
                            {step.description}
                          </p>
                        )}
                      </div>

                      {/* Metadata */}
                      <div className="flex items-center gap-2 flex-shrink-0">
                        {step.duration && (
                          <span className="text-xs text-gray-500">
                            {step.duration}ms
                          </span>
                        )}
                        
                        {step.confidence !== undefined && (
                          <div className="flex items-center gap-1">
                            <div className="w-12 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                              <div 
                                className={cn(
                                  "h-full transition-all",
                                  getConfidenceColor(step.confidence)
                                )}
                                style={{ width: `${step.confidence}%` }}
                              />
                            </div>
                            <span className="text-xs text-gray-500">
                              {step.confidence}%
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Expanded content */}
                  {isExpanded && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="border-t border-purple-500/20 p-3 bg-black/20"
                    >
                      <p className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
                        {step.description}
                      </p>
                      
                      {step.timestamp && (
                        <div className="mt-2 text-xs text-gray-500">
                          {new Date(step.timestamp).toLocaleTimeString()}
                        </div>
                      )}
                    </motion.div>
                  )}
                </div>
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>

      {/* Summary */}
      {!isStreaming && steps.length > 0 && (
        <div className="mt-4 p-3 rounded-lg bg-purple-950/20 border border-purple-500/20">
          <div className="flex items-center justify-between text-xs">
            <span className="text-gray-400">
              Total Steps: {steps.length}
            </span>
            <span className="text-gray-400">
              Completed: {steps.filter(s => s.status === 'complete').length}
            </span>
            {steps.some(s => s.duration) && (
              <span className="text-gray-400">
                Total Time: {steps.reduce((acc, s) => acc + (s.duration || 0), 0)}ms
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Utility function to parse reasoning text into steps
 */
export function parseReasoningIntoSteps(reasoning: string): ReasoningStep[] {
  const steps: ReasoningStep[] = [];
  
  // Try to detect numbered steps (1., 2., etc.)
  const numberedPattern = /(\d+)\.\s*([^\n]+)/g;
  let match;
  let stepIndex = 1;
  
  while ((match = numberedPattern.exec(reasoning)) !== null) {
    const [_, number, content] = match;
    steps.push({
      id: `step-${stepIndex}`,
      step: stepIndex,
      title: content.substring(0, 50) + (content.length > 50 ? '...' : ''),
      description: content,
      status: 'complete',
      type: detectStepType(content)
    });
    stepIndex++;
  }
  
  // If no numbered steps found, create a single step
  if (steps.length === 0) {
    steps.push({
      id: 'step-1',
      step: 1,
      title: 'Reasoning',
      description: reasoning,
      status: 'complete',
      type: 'analysis'
    });
  }
  
  return steps;
}

function detectStepType(content: string): ReasoningStep['type'] {
  const lower = content.toLowerCase();
  
  if (lower.includes('analyze') || lower.includes('check') || lower.includes('examine')) {
    return 'analysis';
  }
  if (lower.includes('decide') || lower.includes('choose') || lower.includes('select')) {
    return 'decision';
  }
  if (lower.includes('execute') || lower.includes('run') || lower.includes('perform')) {
    return 'action';
  }
  if (lower.includes('verify') || lower.includes('validate') || lower.includes('confirm')) {
    return 'validation';
  }
  
  return 'analysis';
}

export default ReasoningSteps;
