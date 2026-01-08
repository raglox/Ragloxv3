// Enhanced Toast Component for Better Error Visibility
// Addresses issue: Error messages appear small and unclear in top corner

import { toast as sonnerToast, type ExternalToast } from "sonner";
import { AlertCircle, CheckCircle, Info, AlertTriangle, XCircle } from "lucide-react";

export interface EnhancedToastOptions extends ExternalToast {
  title?: string;
  description?: string;
  variant?: "default" | "destructive" | "success" | "warning" | "info";
}

// Enhanced toast with better visibility
export const enhancedToast = {
  success: (message: string, options?: EnhancedToastOptions) => {
    return sonnerToast.success(message, {
      ...options,
      icon: <CheckCircle className="w-5 h-5" />,
      className: "enhanced-toast enhanced-toast-success",
      style: {
        background: "hsl(var(--success) / 0.1)",
        borderLeft: "4px solid hsl(var(--success))",
        padding: "16px",
        fontSize: "14px",
        minWidth: "400px",
      },
      duration: options?.duration || 4000,
    });
  },

  error: (message: string, options?: EnhancedToastOptions) => {
    return sonnerToast.error(message, {
      ...options,
      icon: <XCircle className="w-5 h-5" />,
      className: "enhanced-toast enhanced-toast-error",
      style: {
        background: "hsl(var(--destructive) / 0.1)",
        borderLeft: "4px solid hsl(var(--destructive))",
        padding: "16px",
        fontSize: "14px",
        minWidth: "400px",
      },
      duration: options?.duration || 6000, // Longer for errors
    });
  },

  warning: (message: string, options?: EnhancedToastOptions) => {
    return sonnerToast.warning(message, {
      ...options,
      icon: <AlertTriangle className="w-5 h-5" />,
      className: "enhanced-toast enhanced-toast-warning",
      style: {
        background: "hsl(var(--warning) / 0.1)",
        borderLeft: "4px solid hsl(var(--warning))",
        padding: "16px",
        fontSize: "14px",
        minWidth: "400px",
      },
      duration: options?.duration || 5000,
    });
  },

  info: (message: string, options?: EnhancedToastOptions) => {
    return sonnerToast.info(message, {
      ...options,
      icon: <Info className="w-5 h-5" />,
      className: "enhanced-toast enhanced-toast-info",
      style: {
        background: "hsl(var(--info) / 0.1)",
        borderLeft: "4px solid hsl(var(--info))",
        padding: "16px",
        fontSize: "14px",
        minWidth: "400px",
      },
      duration: options?.duration || 4000,
    });
  },

  // Connection error with retry option
  connectionError: (message: string, onRetry?: () => void) => {
    return sonnerToast.error(message, {
      icon: <AlertCircle className="w-5 h-5" />,
      className: "enhanced-toast enhanced-toast-connection-error",
      style: {
        background: "hsl(var(--destructive) / 0.15)",
        borderLeft: "4px solid hsl(var(--destructive))",
        padding: "20px",
        fontSize: "15px",
        minWidth: "450px",
        fontWeight: "500",
      },
      duration: 8000,
      action: onRetry ? {
        label: "Retry",
        onClick: onRetry,
      } : undefined,
    });
  },

  // Backend unavailable with clear message
  backendUnavailable: () => {
    return sonnerToast.error("Backend API Unavailable", {
      description: "Unable to connect to the backend server. Please check if the server is running and try again.",
      icon: <AlertCircle className="w-6 h-6" />,
      className: "enhanced-toast enhanced-toast-critical",
      style: {
        background: "hsl(var(--destructive) / 0.2)",
        borderLeft: "6px solid hsl(var(--destructive))",
        padding: "24px",
        fontSize: "16px",
        minWidth: "500px",
        fontWeight: "600",
        boxShadow: "0 10px 40px rgba(0, 0, 0, 0.3)",
      },
      duration: 10000,
    });
  },
};

// Export enhanced toast as default
export { enhancedToast as toast };
export default enhancedToast;
