// RAGLOX v3.0 - Streaming Chat Hook
// React hook for AI response streaming via Server-Sent Events (SSE)
// Provides real-time token-by-token response display

import { useState, useCallback, useRef } from "react";
import { API_BASE_URL } from "@/lib/config";
import { getAuthHeaders } from "@/lib/api";

// ============================================
// Types
// ============================================

export interface StreamingMessage {
  id: string;
  content: string;
  isComplete: boolean;
  isStreaming: boolean;
  command?: string;
  terminalOutput: string[];
  terminalStatus: "idle" | "running" | "complete" | "error";
  error?: string;
}

export interface UseStreamingChatOptions {
  onChunk?: (chunk: string) => void;
  onStart?: (messageId: string) => void;
  onEnd?: (messageId: string) => void;
  onError?: (error: string) => void;
  onCommand?: (command: string) => void;
  onTerminalOutput?: (line: string) => void;
  onTerminalComplete?: (exitCode: number) => void;
}

export interface UseStreamingChatResult {
  // State
  streamingMessage: StreamingMessage | null;
  isStreaming: boolean;
  error: string | null;

  // Actions
  sendStreamingMessage: (content: string, relatedTaskId?: string, relatedActionId?: string) => Promise<void>;
  cancelStream: () => void;
  clearStreamingMessage: () => void;
}

// ============================================
// useStreamingChat Hook
// ============================================

export function useStreamingChat(
  missionId: string,
  options: UseStreamingChatOptions = {}
): UseStreamingChatResult {
  const {
    onChunk,
    onStart,
    onEnd,
    onError,
    onCommand,
    onTerminalOutput,
    onTerminalComplete,
  } = options;

  // State
  const [streamingMessage, setStreamingMessage] = useState<StreamingMessage | null>(null);
  const [isStreaming, setIsStreaming] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Refs for cancellation
  const abortControllerRef = useRef<AbortController | null>(null);
  const readerRef = useRef<ReadableStreamDefaultReader<Uint8Array> | null>(null);

  /**
   * Send a message and stream the AI response
   */
  const sendStreamingMessage = useCallback(
    async (
      content: string,
      relatedTaskId?: string,
      relatedActionId?: string
    ): Promise<void> => {
      // Cancel any existing stream
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }

      // Reset state
      setError(null);
      setIsStreaming(true);
      setStreamingMessage({
        id: "",
        content: "",
        isComplete: false,
        isStreaming: true,
        terminalOutput: [],
        terminalStatus: "idle",
      });

      // Create abort controller
      abortControllerRef.current = new AbortController();

      try {
        const response = await fetch(
          `${API_BASE_URL}/api/v1/missions/${missionId}/chat/stream`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...getAuthHeaders(),
            },
            body: JSON.stringify({
              content,
              related_task_id: relatedTaskId,
              related_action_id: relatedActionId,
            }),
            signal: abortControllerRef.current.signal,
          }
        );

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.detail || `HTTP ${response.status}`);
        }

        if (!response.body) {
          throw new Error("Response body is null");
        }

        // Get reader for streaming
        const reader = response.body.getReader();
        readerRef.current = reader;
        const decoder = new TextDecoder();

        let buffer = "";

        // Read stream
        while (true) {
          const { done, value } = await reader.read();

          if (done) {
            break;
          }

          // Decode chunk and add to buffer
          buffer += decoder.decode(value, { stream: true });

          // Process complete SSE messages
          const lines = buffer.split("\n\n");
          buffer = lines.pop() || ""; // Keep incomplete line in buffer

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const data = JSON.parse(line.slice(6));
                handleSSEEvent(data);
              } catch (e) {
                console.warn("[StreamingChat] Failed to parse SSE data:", e);
              }
            }
          }
        }

        // Process any remaining data in buffer
        if (buffer.startsWith("data: ")) {
          try {
            const data = JSON.parse(buffer.slice(6));
            handleSSEEvent(data);
          } catch (e) {
            // Ignore parse errors for incomplete data
          }
        }
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") {
          console.log("[StreamingChat] Stream cancelled");
          return;
        }

        const errorMessage = err instanceof Error ? err.message : "Unknown error";
        setError(errorMessage);
        setStreamingMessage((prev) =>
          prev
            ? { ...prev, isStreaming: false, isComplete: true, error: errorMessage }
            : null
        );
        onError?.(errorMessage);
      } finally {
        setIsStreaming(false);
        abortControllerRef.current = null;
        readerRef.current = null;
      }
    },
    [missionId, onChunk, onStart, onEnd, onError, onCommand, onTerminalOutput, onTerminalComplete]
  );

  /**
   * Handle SSE event
   */
  const handleSSEEvent = useCallback(
    (data: Record<string, unknown>) => {
      const eventType = data.type as string;

      switch (eventType) {
        case "start":
          {
            const messageId = data.message_id as string;
            setStreamingMessage((prev) =>
              prev ? { ...prev, id: messageId } : null
            );
            onStart?.(messageId);
          }
          break;

        case "chunk":
          {
            const chunk = data.content as string;
            setStreamingMessage((prev) =>
              prev ? { ...prev, content: prev.content + chunk } : null
            );
            onChunk?.(chunk);
          }
          break;

        case "command":
          {
            const command = data.command as string;
            setStreamingMessage((prev) =>
              prev ? { ...prev, command } : null
            );
            onCommand?.(command);
          }
          break;

        case "terminal_start":
          {
            const command = data.command as string;
            setStreamingMessage((prev) =>
              prev
                ? {
                    ...prev,
                    command,
                    terminalStatus: "running",
                    terminalOutput: [],
                  }
                : null
            );
          }
          break;

        case "terminal_output":
          {
            const line = data.line as string;
            setStreamingMessage((prev) =>
              prev
                ? {
                    ...prev,
                    terminalOutput: [...prev.terminalOutput, line],
                  }
                : null
            );
            onTerminalOutput?.(line);
          }
          break;

        case "terminal_complete":
          {
            const exitCode = data.exit_code as number;
            setStreamingMessage((prev) =>
              prev
                ? {
                    ...prev,
                    terminalStatus: exitCode === 0 ? "complete" : "error",
                  }
                : null
            );
            onTerminalComplete?.(exitCode);
          }
          break;

        case "end":
          {
            const messageId = data.message_id as string;
            setStreamingMessage((prev) =>
              prev
                ? { ...prev, isStreaming: false, isComplete: true }
                : null
            );
            onEnd?.(messageId);
          }
          break;

        case "error":
          {
            const errorMsg = data.message as string;
            setError(errorMsg);
            setStreamingMessage((prev) =>
              prev
                ? {
                    ...prev,
                    isStreaming: false,
                    isComplete: true,
                    error: errorMsg,
                  }
                : null
            );
            onError?.(errorMsg);
          }
          break;

        case "cancelled":
          {
            setStreamingMessage((prev) =>
              prev
                ? { ...prev, isStreaming: false, isComplete: false }
                : null
            );
          }
          break;

        default:
          console.log("[StreamingChat] Unknown event type:", eventType, data);
      }
    },
    [onChunk, onStart, onEnd, onError, onCommand, onTerminalOutput, onTerminalComplete]
  );

  /**
   * Cancel the current stream
   */
  const cancelStream = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    if (readerRef.current) {
      readerRef.current.cancel().catch(() => {});
    }
    setIsStreaming(false);
    setStreamingMessage((prev) =>
      prev ? { ...prev, isStreaming: false } : null
    );
  }, []);

  /**
   * Clear the streaming message
   */
  const clearStreamingMessage = useCallback(() => {
    setStreamingMessage(null);
    setError(null);
  }, []);

  return {
    streamingMessage,
    isStreaming,
    error,
    sendStreamingMessage,
    cancelStream,
    clearStreamingMessage,
  };
}

export default useStreamingChat;
