import { useState, useRef, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Plus,
  Mic,
  Brain,
  Check,
  Circle,
  Loader2,
  Monitor,
  Sparkles,
  ArrowDown,
  Terminal,
  ChevronDown,
  ChevronUp,
  Target,
  Shield
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { ChatMessage, EventCard as EventCardType, PlanTask, ConnectionStatus } from "@/types";
import { ApprovalCard } from "./ApprovalCard";
import { AIPlanCard } from "./AIPlanCard";
import { CredentialCard, SessionCard, VulnerabilityCard, TargetCard } from "./ArtifactCard";
import RichMessage from "../chat/RichMessage";
import { useAutoScroll } from "../../hooks/useAutoScroll";

interface AIChatPanelProps {
  messages: ChatMessage[];
  events: EventCardType[];
  planTasks: PlanTask[];
  onSendMessage: (content: string) => void;
  onCommandClick?: (command: string) => void;
  onExpandTerminal?: () => void;
  onApprove?: (actionId: string, comment?: string) => void;
  onReject?: (actionId: string, reason?: string, comment?: string) => void;
  isConnected?: boolean;
  connectionStatus?: ConnectionStatus;
  terminalLastCommand?: string;
  terminalPreviewLines?: string[];
  className?: string;
  showDemoData?: boolean;
  isAITyping?: boolean;
}

export function AIChatPanel({
  messages,
  events,
  planTasks,
  onSendMessage,
  onCommandClick,
  onExpandTerminal,
  onApprove,
  onReject,
  isConnected = false,
  connectionStatus = "disconnected",
  className,
  isAITyping = false,
}: AIChatPanelProps) {
  const [inputValue, setInputValue] = useState("");
  const [isPlanExpanded, setIsPlanExpanded] = useState(false);
  const [collapsedEvents, setCollapsedEvents] = useState<Set<string>>(new Set());
  const [expandedKnowledge, setExpandedKnowledge] = useState<Set<string>>(new Set());
  const [isSending, setIsSending] = useState(false);
  
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll integration
  const { containerRef, showScrollButton, scrollToBottom, handleScroll } = useAutoScroll([messages, events, isAITyping]);

  const hasConversationStarted = useMemo(() => {
    return messages.length > 0 || events.length > 0;
  }, [messages, events]);

  // Auto-resize textarea
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.style.height = "auto";
      inputRef.current.style.height = `${Math.min(inputRef.current.scrollHeight, 200)}px`;
    }
  }, [inputValue]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (inputValue.trim() && !isSending) {
      setIsSending(true);
      onSendMessage(inputValue.trim());
      setInputValue("");
      setTimeout(() => setIsSending(false), 1000);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit(e);
    }
  };

  const toggleEvent = (eventId: string) => {
    setCollapsedEvents(prev => {
      const next = new Set(prev);
      if (next.has(eventId)) next.delete(eventId);
      else next.add(eventId);
      return next;
    });
  };

  const toggleKnowledge = (knowledgeId: string) => {
    setExpandedKnowledge(prev => {
      const next = new Set(prev);
      if (next.has(knowledgeId)) next.delete(knowledgeId);
      else next.add(knowledgeId);
      return next;
    });
  };

  // Plan progress
  const completedTasks = planTasks.filter(t => t.status === "completed").length;
  const totalTasks = planTasks.length;
  const progress = totalTasks > 0 ? (completedTasks / totalTasks) * 100 : 0;
  const hasActivePlan = planTasks.length > 0;

  // Initial State (Centered)
  if (!hasConversationStarted) {
    return (
      <div className={cn("flex flex-col h-full overflow-hidden bg-[#1a1a1a]", className)}>
        <Header connectionStatus={connectionStatus} isConnected={isConnected} />
        
        <div className="flex-1 flex flex-col items-center justify-center px-6">
          <div className="w-full max-w-[600px] text-center">
            <motion.h1 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-4xl font-semibold mb-4 text-[#e8e8e8]"
            >
              What can I do for you?
            </motion.h1>
            
            <motion.p 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="text-lg mb-8 text-[#888888]"
            >
              Give RAGLOX a task to work on...
            </motion.p>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="mb-6"
            >
              <form onSubmit={handleSubmit}>
                <div className="chat-input chat-input-centered" style={{ boxShadow: '0 4px 24px rgba(0,0,0,0.3)', border: '1px solid rgba(255,255,255,0.1)' }}>
                  <button type="button" className="chat-input-btn"><Plus className="w-4 h-4" /></button>
                  <textarea
                    ref={inputRef}
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    onKeyDown={handleKeyDown}
                    placeholder={isSending ? "Please wait..." : "Describe your security task..."}
                    className="chat-input-field min-h-[40px] max-h-[200px] py-2"
                    rows={1}
                    disabled={isSending || !isConnected}
                  />
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <button type="button" className="chat-input-btn"><Mic className="w-4 h-4" /></button>
                    <button type="submit" className={cn("chat-input-send", inputValue.trim() && "active")} disabled={!inputValue.trim()}>
                      <ArrowDown className="w-4 h-4 rotate-180" />
                    </button>
                  </div>
                </div>
              </form>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
            >
              <InitialQuickActions onAction={onSendMessage} />
            </motion.div>
          </div>
        </div>
      </div>
    );
  }

  // Active State
  return (
    <div className={cn("flex flex-col h-full overflow-hidden bg-[#1a1a1a]", className)}>
      <Header connectionStatus={connectionStatus} isConnected={isConnected} />

      {/* Messages Area */}
      <div 
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto min-h-0 scroll-smooth"
      >
        <div className="flex justify-center w-full py-6 pb-40 px-6">
          <div className="w-full max-w-[800px] flex flex-col gap-6">
            
            {/* Agent Header */}
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full flex items-center justify-center bg-[#4a9eff]/15">
                <Brain className="w-4 h-4 text-[#4a9eff]" />
              </div>
              <span className="font-semibold text-[#e8e8e8] text-base">RAGLOX</span>
              <span className="agent-badge">v3.0</span>
            </div>

            {/* Messages & Events */}
            {messages.map((message) => (
              <ChatMessageItem key={message.id || message.timestamp} message={message} />
            ))}

            {isAITyping && <TypingIndicator />}

            {events.map((event) => (
               <EventItemWrapper 
                  key={event.id}
                  event={event}
                  isExpanded={!collapsedEvents.has(event.id)}
                  onToggle={() => toggleEvent(event.id)}
                  expandedKnowledge={expandedKnowledge}
                  onToggleKnowledge={toggleKnowledge}
                  onCommandClick={onCommandClick}
                  onExpandTerminal={onExpandTerminal}
                  onApprove={onApprove}
                  onReject={onReject}
               />
            ))}
          </div>
        </div>
      </div>
      
      {/* Floating Scroll Button */}
      {showScrollButton && (
          <div className="absolute bottom-24 right-8 z-10">
              <button 
                  onClick={scrollToBottom}
                  className="p-2 bg-blue-600 text-white rounded-full shadow-lg hover:bg-blue-700 transition-colors"
              >
                  <ArrowDown className="w-4 h-4" />
              </button>
          </div>
      )}

      {/* Bottom Input Section */}
      <div className="flex-shrink-0 sticky bottom-0 pt-4 mt-auto bg-gradient-to-b from-transparent via-[#1a1a1a] to-[#1a1a1a]">
        <div className="flex justify-center w-full px-6 pb-4">
          <div className="w-full max-w-[800px]">
            {/* Plan Overlay */}
            <AnimatePresence>
                {isPlanExpanded && hasActivePlan && (
                  <PlanOverlay 
                    tasks={planTasks} 
                    completed={completedTasks} 
                    total={totalTasks} 
                    progress={progress} 
                    onClose={() => setIsPlanExpanded(false)} 
                  />
                )}
            </AnimatePresence>

            {/* Collapsed Plan Bar */}
            {hasActivePlan && !isPlanExpanded && (
              <div className="flex items-center justify-center mb-2">
                <button
                  onClick={() => setIsPlanExpanded(true)}
                  className="flex items-center gap-2 px-4 py-2 rounded-full transition-all bg-[#262626]/90 backdrop-blur-sm shadow-sm hover:bg-[#303030]/95"
                >
                  <Monitor className="w-4 h-4 text-[#A3A3A3]" />
                  <span className="text-sm text-[#E5E5E5]">Task Progress</span>
                  <span className="text-sm text-[#A3A3A3]">{completedTasks}/{totalTasks}</span>
                  <ChevronUp className="w-4 h-4 text-[#A3A3A3]" />
                </button>
              </div>
            )}

            <QuickActionsBar onAction={onSendMessage} />

            <form onSubmit={handleSubmit}>
              <div className="chat-input" style={{ boxShadow: 'var(--shadow-card)' }}>
                <button type="button" className="chat-input-btn"><Plus className="w-4 h-4" /></button>
                <textarea
                  ref={inputRef}
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={isSending ? "Please wait..." : "Send message to RAGLOX"}
                  className="chat-input-field min-h-[32px] max-h-[200px] py-1.5"
                  rows={1}
                  disabled={isSending || !isConnected}
                />
                <div className="flex items-center gap-1 flex-shrink-0">
                  <button type="button" className="chat-input-btn"><Mic className="w-4 h-4" /></button>
                  <button type="submit" className={cn("chat-input-send", inputValue.trim() && "active")} disabled={!inputValue.trim()}>
                    <ArrowDown className="w-4 h-4 rotate-180" />
                  </button>
                </div>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}

// Sub-components

function Header({ connectionStatus, isConnected }: { connectionStatus: any, isConnected: boolean }) {
  return (
    <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
      <div className="flex items-center gap-2">
        <span className="font-medium text-foreground">RAGLOX 3.0</span>
        <ChevronDown className="w-4 h-4 text-muted-foreground" />
      </div>
      <div className="flex items-center gap-1.5">
          <div className={cn("w-2 h-2 rounded-full", isConnected ? "bg-green-500 shadow-[0_0_6px_rgba(74,222,128,0.5)]" : "bg-red-500")} />
          <span className={cn("text-xs", isConnected ? "text-green-500" : "text-red-500")}>
            {isConnected ? "Live" : connectionStatus}
          </span>
      </div>
    </div>
  );
}

function ChatMessageItem({ message }: { message: ChatMessage }) {
  const { role, content, status, error, isOptimistic } = message;
  if (!content) return null;

  const isUser = role === "user";

  return (
    <div className={cn("flex items-start gap-3", isUser ? "opacity-100" : "")}>
      {!isUser && (
        <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 bg-[#4a9eff]/15">
          <Brain className="w-4 h-4 text-[#4a9eff]" />
        </div>
      )}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-sm font-medium text-[#e8e8e8]">{isUser ? "You" : "RAGLOX"}</span>
          {status === "sending" && <span className="text-xs text-[#4a9eff] flex items-center gap-1"><Loader2 className="w-3 h-3 animate-spin"/> Sending...</span>}
          {status === "streaming" && <span className="text-xs text-[#4a9eff] animate-pulse">Typing...</span>}
          {error && <span className="text-xs text-red-500">Failed</span>}
        </div>
        
        <div className={cn("text-sm leading-relaxed text-[#e8e8e8]", isOptimistic && "opacity-70")}>
            <RichMessage content={content} role={role} />
        </div>
        
        {error && <p className="text-xs mt-1 text-red-500">{error}</p>}
      </div>
    </div>
  );
}

function TypingIndicator() {
  return (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="flex items-start gap-3">
      <div className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 bg-[#4a9eff]/15">
        <Brain className="w-4 h-4 text-[#4a9eff]" />
      </div>
      <div className="flex-1">
         <span className="text-sm font-medium text-[#e8e8e8] block mb-1">RAGLOX</span>
         <div className="flex items-center gap-1">
            {[0, 0.2, 0.4].map((delay, i) => (
                <motion.div key={i} className="w-2 h-2 rounded-full bg-[#4a9eff]" animate={{ opacity: [0.3, 1, 0.3] }} transition={{ duration: 1.5, repeat: Infinity, delay }} />
            ))}
         </div>
      </div>
    </motion.div>
  );
}

function InitialQuickActions({ onAction }: { onAction: (a: string) => void }) {
    const actions = [
        { icon: Target, label: "Plan Mission", action: "Help me create a penetration testing plan", color: "#4a9eff" },
        { icon: Shield, label: "Check Env", action: "Check my execution environment status", color: "#f59e0b" },
        { icon: Terminal, label: "Exec Cmd", action: "I want to execute a command", color: "#4ade80" },
        { icon: Sparkles, label: "Status", action: "Show me mission status", color: "#a78bfa" },
    ];
    return (
        <div className="grid grid-cols-2 gap-3">
            {actions.map(a => (
                <button key={a.label} onClick={() => onAction(a.action)} className="flex items-start gap-3 p-4 rounded-xl text-left transition-all duration-200 bg-[#262626]/60 border border-white/5 hover:bg-[#303030]/80">
                    <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${a.color}15` }}>
                        <a.icon className="w-5 h-5" style={{ color: a.color }} />
                    </div>
                    <div>
                        <span className="text-sm font-medium block text-[#e8e8e8]">{a.label}</span>
                    </div>
                </button>
            ))}
        </div>
    );
}

function QuickActionsBar({ onAction }: { onAction: (a: string) => void }) {
    const actions = [
        { icon: Target, label: "Recon", action: "Start reconnaissance", color: "#4a9eff" },
        { icon: Shield, label: "Scan", action: "Scan for vulnerabilities", color: "#f59e0b" },
        { icon: Terminal, label: "Shell", action: "Attempt shell access", color: "#4ade80" },
    ];
    return (
        <div className="flex justify-center mb-3">
            <div className="flex items-center gap-1 px-2 py-1.5 rounded-full bg-[#2a2a2a]/70 backdrop-blur border border-white/5">
                {actions.map(a => (
                    <button key={a.label} onClick={() => onAction(a.action)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium text-[#888888] hover:bg-white/5 hover:text-[#e8e8e8] transition-colors">
                        <a.icon className="w-3.5 h-3.5" />
                        <span>{a.label}</span>
                    </button>
                ))}
            </div>
        </div>
    );
}

function PlanOverlay({ tasks, completed, total, progress, onClose }: any) {
    return (
        <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.95 }}
            className="absolute bottom-full left-1/2 -translate-x-1/2 mb-3 w-[400px] max-w-[90vw] bg-[#1e1e1e]/98 backdrop-blur-xl rounded-2xl shadow-2xl border border-white/10 overflow-hidden"
        >
            <div className="flex items-center justify-between p-4 border-b border-white/5">
                <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-[#4a9eff]/15">
                        <Monitor className="w-4.5 h-4.5 text-[#4a9eff]" />
                    </div>
                    <div>
                        <span className="font-medium text-sm text-[#e8e8e8]">Task Progress</span>
                        <div className="flex items-center gap-1.5 mt-0.5">
                            <Terminal className="w-3 h-3 text-[#888888]" />
                            <span className="text-xs text-[#888888]">RAGLOX Terminal</span>
                        </div>
                    </div>
                </div>
                <span className="text-sm font-medium text-[#888888]">{completed}/{total}</span>
            </div>
            <div className="px-4 py-2">
                <div className="h-1 rounded-full bg-[#2a2a2a] overflow-hidden">
                    <motion.div className="h-full rounded-full bg-[#4a9eff]" initial={{ width: 0 }} animate={{ width: `${progress}%` }} />
                </div>
            </div>
            <div className="px-2 pb-2 max-h-[180px] overflow-y-auto">
                {tasks.map((task: any) => (
                    <div key={task.id} className="flex items-center gap-3 py-2 px-2 rounded-lg hover:bg-white/5">
                        <div className={cn("w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0", task.status === 'completed' ? 'bg-green-500/15' : 'bg-[#2a2a2a]')}>
                            {task.status === 'completed' ? <Check className="w-3 h-3 text-green-500" /> : <Circle className="w-3 h-3 text-[#888888]" />}
                        </div>
                        <span className={cn("text-sm flex-1", task.status === 'completed' ? "text-[#888888]" : "text-[#e8e8e8]")}>{task.title}</span>
                    </div>
                ))}
            </div>
            <button onClick={onClose} className="w-full py-3 text-sm text-[#888888] hover:bg-white/5 border-t border-white/5 flex items-center justify-center gap-2">
                <ChevronDown className="w-4 h-4" /> Hide Plan
            </button>
        </motion.div>
    );
}

function EventItemWrapper({ event, isExpanded, onToggle, expandedKnowledge, onToggleKnowledge, onApprove, onReject, onCommandClick, onExpandTerminal }: any) {
    if (event.type === "approval_request" && event.approval) {
        return <ApprovalCard approval={event.approval} onApprove={onApprove} onReject={onReject} />;
    }
    if (event.type === "ai_plan" && event.aiPlan) {
        return <AIPlanCard data={event.aiPlan} />;
    }
    if (event.type === "artifact" && event.artifact) {
         // Simplified artifact rendering
         return <div className="text-white">Artifact: {event.title}</div>;
    }
    
    // Regular event
    return (
        <div className="space-y-2">
            <button onClick={onToggle} className="flex items-center gap-2 w-full text-left group py-2">
                 <div className={cn("w-5 h-5 rounded-full flex items-center justify-center", event.status === "completed" ? "bg-green-500/15" : "bg-[#2a2a2a]")}>
                    {event.status === "completed" ? <Check className="w-3 h-3 text-green-500" /> : <Circle className="w-3 h-3 text-[#888888]" />}
                 </div>
                 <span className="font-medium flex-1 text-[#e8e8e8]">{event.title}</span>
                 <ChevronUp className={cn("w-4 h-4 text-[#888888] transition-transform", !isExpanded && "rotate-180")} />
            </button>
            <AnimatePresence>
                {isExpanded && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
                        <div className="pl-7 pt-1 space-y-3">
                             {event.description && <p className="text-sm leading-relaxed text-[#888888]">{event.description}</p>}
                             {event.command && (
                                <button onClick={() => { onCommandClick?.(event.command); onExpandTerminal?.(); }} className="command-pill">
                                    <Terminal className="icon" /> <span>Executing</span> <code>{event.command}</code>
                                </button>
                             )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
