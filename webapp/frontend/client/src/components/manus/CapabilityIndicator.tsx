// RAGLOX v3.0 - Capability Level Indicator Component
// Shows current execution capability level with clear visual indicators
// Addresses GAP-UX-001: Shell Access Promise vs. Reality Mismatch

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, Cloud, Activity, Zap, AlertCircle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { motion } from "framer-motion";

export type CapabilityLevel = 0 | 1 | 2 | 3;

export interface VMStatus {
  status: "not_created" | "creating" | "ready" | "error" | "unknown";
  progress?: number;
  message?: string;
  vm_id?: string;
  ip?: string;
}

interface CapabilityIndicatorProps {
  level: CapabilityLevel;
  vmStatus?: VMStatus;
  className?: string;
  showLabel?: boolean;
  compact?: boolean;
}

const LEVEL_CONFIG = {
  0: {
    label: "Offline",
    description: "No backend connection - UI only mode",
    icon: Shield,
    color: "text-gray-500",
    bgColor: "bg-gray-500/10",
    borderColor: "border-gray-500/20"
  },
  1: {
    label: "Connected",
    description: "Backend API connected - Create mission to start",
    icon: Cloud,
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    borderColor: "border-blue-500/20"
  },
  2: {
    label: "Simulation",
    description: "Commands run in simulation mode - VM provisioning in progress",
    icon: Activity,
    color: "text-yellow-500",
    bgColor: "bg-yellow-500/10",
    borderColor: "border-yellow-500/20"
  },
  3: {
    label: "Real Execution",
    description: "Commands execute on live target environment",
    icon: Zap,
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    borderColor: "border-green-500/20"
  }
};

export function CapabilityIndicator({
  level,
  vmStatus,
  className,
  showLabel = true,
  compact = false
}: CapabilityIndicatorProps) {
  const config = LEVEL_CONFIG[level];
  const Icon = config.icon;

  if (compact) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div className={cn("flex items-center gap-1.5", className)}>
            {/* Level dots */}
            <div className="flex items-center gap-0.5">
              {[0, 1, 2, 3].map((i) => (
                <motion.div
                  key={i}
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ 
                    scale: i <= level ? 1 : 0.8,
                    opacity: i <= level ? 1 : 0.3
                  }}
                  transition={{ delay: i * 0.1, duration: 0.2 }}
                  className={cn(
                    "w-1.5 h-1.5 rounded-full transition-all",
                    config.color
                  )}
                  style={{
                    backgroundColor: i <= level ? 'currentColor' : 'transparent',
                    border: `1px solid currentColor`
                  }}
                />
              ))}
            </div>
            <span className={cn("text-xs font-medium", config.color)}>
              L{level}
            </span>
          </div>
        </TooltipTrigger>
        <TooltipContent side="bottom">
          <div className="space-y-1">
            <p className="font-medium">Level {level}: {config.label}</p>
            <p className="text-xs text-muted-foreground">{config.description}</p>
          </div>
        </TooltipContent>
      </Tooltip>
    );
  }

  return (
    <div className={cn("flex items-center gap-3", className)}>
      {/* Level dots */}
      <div className="flex items-center gap-1">
        {[0, 1, 2, 3].map((i) => (
          <motion.div
            key={i}
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ 
              scale: i <= level ? 1 : 0.8,
              opacity: i <= level ? 1 : 0.3
            }}
            transition={{ delay: i * 0.1, duration: 0.2 }}
            className={cn(
              "w-2 h-2 rounded-full transition-all",
              config.color
            )}
            style={{
              backgroundColor: i <= level ? 'currentColor' : 'transparent',
              border: `2px solid currentColor`
            }}
          />
        ))}
      </div>

      {/* Level badge */}
      {showLabel && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Badge
              variant="outline"
              className={cn(
                "gap-1.5 cursor-help",
                config.color,
                config.bgColor,
                config.borderColor
              )}
            >
              <Icon className="w-3 h-3" />
              <span className="font-medium">Level {level}: {config.label}</span>
            </Badge>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-xs">
            <p>{config.description}</p>
            {level === 2 && vmStatus && (
              <p className="mt-2 text-xs text-muted-foreground">
                {vmStatus.status === "creating" && "VM is being provisioned for real execution"}
                {vmStatus.status === "not_created" && "VM not created yet"}
                {vmStatus.status === "error" && "VM provisioning failed"}
              </p>
            )}
            {level === 3 && vmStatus?.vm_id && (
              <p className="mt-2 text-xs text-muted-foreground">
                VM: {vmStatus.vm_id} {vmStatus.ip && `(${vmStatus.ip})`}
              </p>
            )}
          </TooltipContent>
        </Tooltip>
      )}

      {/* VM provisioning indicator */}
      {level === 2 && vmStatus?.status === "creating" && (
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-2"
        >
          <div className="flex items-center gap-1.5">
            <Loader2 className="w-3 h-3 animate-spin text-yellow-500" />
            <span className="text-xs text-muted-foreground">
              Provisioning VM...
            </span>
          </div>
          {vmStatus.progress !== undefined && (
            <>
              <Progress value={vmStatus.progress} className="w-20 h-1.5" />
              <span className="text-xs font-medium text-yellow-500 min-w-[3ch] text-right">
                {Math.round(vmStatus.progress)}%
              </span>
            </>
          )}
        </motion.div>
      )}

      {/* VM error indicator */}
      {level === 2 && vmStatus?.status === "error" && (
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          className="flex items-center gap-1.5"
        >
          <AlertCircle className="w-3 h-3 text-red-500" />
          <span className="text-xs text-red-500">
            VM Error: {vmStatus.message || "Unknown error"}
          </span>
        </motion.div>
      )}

      {/* Simulation warning */}
      {level === 2 && !vmStatus && (
        <Tooltip>
          <TooltipTrigger asChild>
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-yellow-500/10 border border-yellow-500/20">
              <AlertCircle className="w-3 h-3 text-yellow-500" />
              <span className="text-xs text-yellow-500">Simulation Mode</span>
            </div>
          </TooltipTrigger>
          <TooltipContent side="bottom" className="max-w-xs">
            <p>Commands are running in simulation mode.</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Output is representative but not from live systems.
            </p>
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  );
}

// Export wrapper component for easy integration
export function CapabilityLevelDisplay({
  isConnected,
  missionStatus,
  vmStatus,
  className
}: {
  isConnected: boolean;
  missionStatus?: string;
  vmStatus?: VMStatus;
  className?: string;
}) {
  // Calculate capability level based on system state
  const level: CapabilityLevel = (() => {
    if (!isConnected) return 0;
    if (!missionStatus || missionStatus === "created") return 1;
    if (vmStatus?.status === "ready") return 3;
    return 2; // Mission active but VM not ready = simulation
  })();

  return (
    <CapabilityIndicator
      level={level}
      vmStatus={vmStatus}
      className={className}
    />
  );
}

export default CapabilityIndicator;
