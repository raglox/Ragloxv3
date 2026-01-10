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
  Info,
  Crosshair,
  Shield,
  Code,
  Terminal,
  Lock,
  Unlock,
  Search,
  Zap
} from 'lucide-react';
import { cn } from '@/lib/utils';

// ═══════════════════════════════════════════════════════════════
// Intelligence Types - RX Modules & Nuclei Templates
// ═══════════════════════════════════════════════════════════════

interface RXModule {
  rx_module_id: string;
  technique_name: string;
  technique_id: string;
  platform: string;
  elevation_required: boolean;
  description?: string;
}

interface NucleiTemplate {
  template_id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  protocol: string;
  cve_id?: string[];
  cvss_score?: number;
}

interface TacticalIntelligence {
  rx_modules?: RXModule[];
  nuclei_templates?: NucleiTemplate[];
  tactical_decisions?: {
    action: string;
    confidence: number;
    reasoning: string;
  }[];
  evasion_strategies?: string[];
  situation_summary?: string;
  mission_phase?: string;
  progress_percentage?: number;
}

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
  intelligence?: TacticalIntelligence; // NEW: Tactical intelligence data
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

                      {/* Tactical Intelligence Display */}
                      {step.intelligence && (
                        <TacticalIntelligenceDisplay intelligence={step.intelligence} />
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

// ═══════════════════════════════════════════════════════════════
// Intelligence Display Components
// ═══════════════════════════════════════════════════════════════

interface RXModuleCardProps {
  module: RXModule;
  index: number;
}

function RXModuleCard({ module, index }: RXModuleCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className="group relative flex items-start gap-3 p-3 rounded-lg border border-purple-500/20 bg-gray-900/30 hover:bg-gray-900/50 hover:border-purple-500/40 transition-all"
    >
      {/* Icon */}
      <div className="flex-shrink-0 w-8 h-8 rounded-md bg-purple-500/20 flex items-center justify-center">
        <Crosshair className="w-4 h-4 text-purple-400" />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        {/* Module ID */}
        <div className="flex items-center gap-2 mb-1">
          <code className="text-xs font-mono text-purple-300 bg-purple-950/50 px-2 py-0.5 rounded">
            {module.rx_module_id}
          </code>
          {module.elevation_required && (
            <span className="inline-flex items-center gap-1 text-xs text-amber-400 bg-amber-950/30 px-2 py-0.5 rounded">
              <Lock className="w-3 h-3" />
              Elevation
            </span>
          )}
        </div>

        {/* Technique Name */}
        <div className="text-sm font-medium text-gray-200 mb-1">
          {module.technique_name}
        </div>

        {/* Metadata */}
        <div className="flex items-center gap-3 text-xs text-gray-500">
          <span className="flex items-center gap-1">
            <Terminal className="w-3 h-3" />
            {module.technique_id}
          </span>
          <span className="flex items-center gap-1">
            <Code className="w-3 h-3" />
            {module.platform}
          </span>
        </div>

        {/* Description (if available) */}
        {module.description && (
          <p className="mt-2 text-xs text-gray-400 line-clamp-2">
            {module.description}
          </p>
        )}
      </div>

      {/* Hover effect */}
      <div className="absolute inset-0 rounded-lg bg-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
    </motion.div>
  );
}

interface NucleiTemplateCardProps {
  template: NucleiTemplate;
  index: number;
}

function NucleiTemplateCard({ template, index }: NucleiTemplateCardProps) {
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-400 bg-red-950/30 border-red-500/30';
      case 'high': return 'text-orange-400 bg-orange-950/30 border-orange-500/30';
      case 'medium': return 'text-yellow-400 bg-yellow-950/30 border-yellow-500/30';
      case 'low': return 'text-green-400 bg-green-950/30 border-green-500/30';
      case 'info': return 'text-blue-400 bg-blue-950/30 border-blue-500/30';
      default: return 'text-gray-400 bg-gray-950/30 border-gray-500/30';
    }
  };

  const getSeverityEmoji = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      case 'info': return '🔵';
      default: return '⚪';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className="group relative flex items-start gap-3 p-3 rounded-lg border border-cyan-500/20 bg-gray-900/30 hover:bg-gray-900/50 hover:border-cyan-500/40 transition-all"
    >
      {/* Icon */}
      <div className="flex-shrink-0 w-8 h-8 rounded-md bg-cyan-500/20 flex items-center justify-center">
        <Search className="w-4 h-4 text-cyan-400" />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        {/* Template ID & Severity */}
        <div className="flex items-center gap-2 mb-1 flex-wrap">
          <code className="text-xs font-mono text-cyan-300 bg-cyan-950/50 px-2 py-0.5 rounded">
            {template.template_id}
          </code>
          <span className={cn(
            "inline-flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded border",
            getSeverityColor(template.severity)
          )}>
            {getSeverityEmoji(template.severity)}
            {template.severity.toUpperCase()}
          </span>
        </div>

        {/* Template Name */}
        <div className="text-sm font-medium text-gray-200 mb-1">
          {template.name}
        </div>

        {/* Metadata */}
        <div className="flex items-center gap-3 text-xs text-gray-500 flex-wrap">
          <span className="flex items-center gap-1">
            <Zap className="w-3 h-3" />
            {template.protocol}
          </span>
          {template.cvss_score && (
            <span className="flex items-center gap-1">
              <Target className="w-3 h-3" />
              CVSS: {template.cvss_score}
            </span>
          )}
          {template.cve_id && template.cve_id.length > 0 && (
            <span className="flex items-center gap-1">
              <Shield className="w-3 h-3" />
              {template.cve_id.join(', ')}
            </span>
          )}
        </div>
      </div>

      {/* Hover effect */}
      <div className="absolute inset-0 rounded-lg bg-cyan-500/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
    </motion.div>
  );
}

interface TacticalIntelligenceDisplayProps {
  intelligence: TacticalIntelligence;
}

function TacticalIntelligenceDisplay({ intelligence }: TacticalIntelligenceDisplayProps) {
  const [activeTab, setActiveTab] = useState<'rx' | 'nuclei' | 'decisions'>('rx');

  return (
    <div className="mt-3 space-y-3">
      {/* Header with tabs */}
      <div className="flex items-center gap-2 border-b border-purple-500/20 pb-2">
        <Brain className="w-4 h-4 text-purple-400" />
        <span className="text-sm font-medium text-purple-300">
          Tactical Intelligence
        </span>
        
        {/* Tab buttons */}
        <div className="ml-auto flex gap-1">
          {intelligence.rx_modules && intelligence.rx_modules.length > 0 && (
            <button
              onClick={() => setActiveTab('rx')}
              className={cn(
                "px-3 py-1 text-xs rounded transition-all",
                activeTab === 'rx'
                  ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                  : "text-gray-400 hover:text-gray-300"
              )}
            >
              RX Modules ({intelligence.rx_modules.length})
            </button>
          )}
          {intelligence.nuclei_templates && intelligence.nuclei_templates.length > 0 && (
            <button
              onClick={() => setActiveTab('nuclei')}
              className={cn(
                "px-3 py-1 text-xs rounded transition-all",
                activeTab === 'nuclei'
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-gray-400 hover:text-gray-300"
              )}
            >
              Nuclei ({intelligence.nuclei_templates.length})
            </button>
          )}
          {intelligence.tactical_decisions && intelligence.tactical_decisions.length > 0 && (
            <button
              onClick={() => setActiveTab('decisions')}
              className={cn(
                "px-3 py-1 text-xs rounded transition-all",
                activeTab === 'decisions'
                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                  : "text-gray-400 hover:text-gray-300"
              )}
            >
              Decisions ({intelligence.tactical_decisions.length})
            </button>
          )}
        </div>
      </div>

      {/* Situation Summary */}
      {intelligence.situation_summary && (
        <div className="p-3 rounded-lg bg-purple-950/20 border border-purple-500/20">
          <div className="flex items-start gap-2">
            <Info className="w-4 h-4 text-purple-400 flex-shrink-0 mt-0.5" />
            <div className="flex-1 text-sm text-gray-300">
              <span className="font-medium text-purple-300">Situation:</span>{' '}
              {intelligence.situation_summary}
              {intelligence.mission_phase && (
                <span className="ml-2 text-xs text-gray-400">
                  [Phase: {intelligence.mission_phase}]
                </span>
              )}
              {intelligence.progress_percentage !== undefined && (
                <span className="ml-2 text-xs text-gray-400">
                  [Progress: {intelligence.progress_percentage.toFixed(1)}%]
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab Content */}
      <AnimatePresence mode="wait">
        {activeTab === 'rx' && intelligence.rx_modules && intelligence.rx_modules.length > 0 && (
          <motion.div
            key="rx"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-2"
          >
            <div className="text-xs text-gray-400 mb-2 flex items-center gap-2">
              <Crosshair className="w-3 h-3" />
              <span>Recommended RX Modules (Atomic Red Team)</span>
            </div>
            {intelligence.rx_modules.map((module, index) => (
              <RXModuleCard key={module.rx_module_id} module={module} index={index} />
            ))}
          </motion.div>
        )}

        {activeTab === 'nuclei' && intelligence.nuclei_templates && intelligence.nuclei_templates.length > 0 && (
          <motion.div
            key="nuclei"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-2"
          >
            <div className="text-xs text-gray-400 mb-2 flex items-center gap-2">
              <Search className="w-3 h-3" />
              <span>Recommended Nuclei Scans</span>
            </div>
            {intelligence.nuclei_templates.map((template, index) => (
              <NucleiTemplateCard key={template.template_id} template={template} index={index} />
            ))}
          </motion.div>
        )}

        {activeTab === 'decisions' && intelligence.tactical_decisions && intelligence.tactical_decisions.length > 0 && (
          <motion.div
            key="decisions"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="space-y-2"
          >
            <div className="text-xs text-gray-400 mb-2 flex items-center gap-2">
              <Lightbulb className="w-3 h-3" />
              <span>Tactical Decisions</span>
            </div>
            {intelligence.tactical_decisions.map((decision, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className="p-3 rounded-lg border border-amber-500/20 bg-gray-900/30"
              >
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div className="flex items-center gap-2">
                    <Target className="w-4 h-4 text-amber-400" />
                    <span className="text-sm font-medium text-gray-200">
                      {decision.action}
                    </span>
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <div className="w-16 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-amber-500 transition-all"
                        style={{ width: `${decision.confidence * 100}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-500">
                      {(decision.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                </div>
                <p className="text-xs text-gray-400 leading-relaxed">
                  {decision.reasoning}
                </p>
              </motion.div>
            ))}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Evasion Strategies */}
      {intelligence.evasion_strategies && intelligence.evasion_strategies.length > 0 && (
        <div className="p-3 rounded-lg bg-indigo-950/20 border border-indigo-500/20">
          <div className="flex items-start gap-2 mb-2">
            <Shield className="w-4 h-4 text-indigo-400 flex-shrink-0 mt-0.5" />
            <span className="text-xs font-medium text-indigo-300">Evasion Strategies</span>
          </div>
          <ul className="space-y-1 ml-6">
            {intelligence.evasion_strategies.map((strategy, index) => (
              <li key={index} className="text-xs text-gray-400 list-disc">
                {strategy}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default ReasoningSteps;

// Export types for external use
export type { 
  ReasoningStep, 
  ReasoningStepsProps,
  RXModule,
  NucleiTemplate,
  TacticalIntelligence
};
