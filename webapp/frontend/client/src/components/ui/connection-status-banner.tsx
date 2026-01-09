// Enhanced Connection Status Banner
// Provides clear, prominent feedback about backend connectivity

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertCircle, Wifi, WifiOff, RefreshCw, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface ConnectionStatusBannerProps {
  isConnected: boolean;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  className?: string;
}

export function ConnectionStatusBanner({
  isConnected,
  isLoading = false,
  error = null,
  onRetry,
  className,
}: ConnectionStatusBannerProps) {
  const [isVisible, setIsVisible] = useState(!isConnected);
  const [isDismissed, setIsDismissed] = useState(false);

  // Show banner when disconnected or error
  useEffect(() => {
    if (!isConnected || error) {
      setIsVisible(true);
      setIsDismissed(false);
    } else {
      // Hide after 2 seconds when connected
      const timer = setTimeout(() => {
        setIsVisible(false);
      }, 2000);
      return () => clearTimeout(timer);
    }
  }, [isConnected, error]);

  // Don't render if dismissed or not visible
  if (isDismissed || (!isVisible && isConnected && !error)) {
    return null;
  }

  const handleDismiss = () => {
    setIsDismissed(true);
    setIsVisible(false);
  };

  const handleRetry = () => {
    onRetry?.();
  };

  // Connected state
  if (isConnected && !error) {
    return (
      <AnimatePresence>
        {isVisible && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className={cn(
              "fixed top-4 left-1/2 -translate-x-1/2 z-50",
              "flex items-center gap-3 px-6 py-3 rounded-full",
              "bg-green-500/20 border border-green-500/30",
              "backdrop-blur-md shadow-lg",
              className
            )}
          >
            <Wifi className="w-5 h-5 text-green-500" />
            <span className="text-sm font-medium text-green-500">
              Connected to backend
            </span>
          </motion.div>
        )}
      </AnimatePresence>
    );
  }

  // Disconnected/Error state
  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          className={cn(
            "fixed top-4 left-1/2 -translate-x-1/2 z-50",
            "min-w-[500px] max-w-[600px]",
            className
          )}
        >
          <div
            className={cn(
              "flex items-start gap-4 p-5 rounded-xl",
              "bg-red-500/20 border-2 border-red-500/40",
              "backdrop-blur-md shadow-2xl",
              "ring-2 ring-red-500/20"
            )}
          >
            {/* Icon */}
            <div className="flex-shrink-0">
              {isLoading ? (
                <RefreshCw className="w-6 h-6 text-red-400 animate-spin" />
              ) : (
                <AlertCircle className="w-6 h-6 text-red-400" />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 space-y-2">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3 className="text-base font-semibold text-white">
                    Backend Connection Failed
                  </h3>
                  <p className="text-sm text-red-100 mt-1">
                    {error || "Unable to connect to the backend API. The server may be offline or unreachable."}
                  </p>
                </div>
                
                {/* Close button */}
                <button
                  onClick={handleDismiss}
                  className="flex-shrink-0 p-1 rounded-md hover:bg-red-500/20 transition-colors"
                  aria-label="Dismiss"
                >
                  <XCircle className="w-5 h-5 text-red-300" />
                </button>
              </div>

              {/* Actions */}
              <div className="flex items-center gap-3 mt-3">
                {onRetry && (
                  <Button
                    onClick={handleRetry}
                    disabled={isLoading}
                    size="sm"
                    className="bg-red-500 hover:bg-red-600 text-white font-medium"
                  >
                    {isLoading ? (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                        Retrying...
                      </>
                    ) : (
                      <>
                        <RefreshCw className="w-4 h-4 mr-2" />
                        Retry Connection
                      </>
                    )}
                  </Button>
                )}

                <span className="text-xs text-red-200">
                  Please ensure the backend server is running on port 8000
                </span>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

export default ConnectionStatusBanner;
