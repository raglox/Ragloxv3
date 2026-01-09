# RAGLOX Chat Interface Implementation Specification

## 1. Overview
This document outlines the technical implementation details for the "User Experience TLC" and "State Management Overhaul" of the RAGLOX chat interface. The goal is to modernize the chat experience to match competitors like Manus and Lovable, focusing on streaming responses, rich markdown rendering, robust state management, and reliability.

## 2. Frontend Implementation Details

### 2.1. Chat Message Type Definitions
Update `src/types.ts` to include robust status tracking.

```typescript
export type MessageStatus = 'sending' | 'sent' | 'streaming' | 'complete' | 'error';

export interface ChatMessage {
    id: string;
    role: 'user' | 'assistant' | 'system';
    content: string;
    timestamp: string;
    // New fields
    status: MessageStatus;
    isOptimistic?: boolean;
    error?: string; // Error message if status is 'error'
    relatedTaskId?: string; // Link to a plan task
}
```

### 2.2. Mission Store Updates (`src/stores/missionStore.ts`)
Refactor `sendMessage` and WebSocket handling to support the new flows.

*   **Optimistic Updates**:
    *   `sendMessage(content)`:
        1.  Generate a temporary UUID.
        2.  Add a message to the store with `status: 'sending'`, `isOptimistic: true`.
        3.  Call API.
        4.  On success: Update message `status: 'sent'`, replace ID with backend ID if provided, clear `isOptimistic`.
        5.  On error: Update message `status: 'error'`, `error: 'Failed to send...'`.

*   **WebSocket Streaming Handling**:
    *   `ai_response_start`:
        *   Check if a message with the given ID exists.
        *   If not, create one with `status: 'streaming'`, `role: 'assistant'`.
        *   If yes (rare, maybe duplicate), update status to `streaming`.
        *   Set `isAITyping = true`.
    *   `ai_token_chunk`:
        *   Find message by ID.
        *   Append `chunk` to `content`.
        *   Ensure `status` is `streaming`.
    *   `ai_response_end`:
        *   Find message by ID.
        *   Set `status: 'complete'`.
        *   Set `isAITyping = false`.

### 2.3. Markdown & Code Rendering
Create a new component `src/components/chat/RichMessage.tsx` using `react-markdown`.

*   **Dependencies**: `react-markdown`, `rehype-highlight`, `remark-gfm`.
*   **Styling**: Use Tailwind typography plugin or custom CSS for distinct message types.
*   **Code Blocks**: Custom renderer for `code` tags to include a "Copy" button and language badge.

### 2.4. Auto-Scroll Hook (`src/hooks/useAutoScroll.ts`)
*   Ref: `containerRef`.
*   Logic:
    *   On new message (dependency array), check `scrollHeight - scrollTop - clientHeight < threshold`.
    *   If true (user was at bottom), scroll to bottom.
    *   If false (user scrolled up), show "New messages" floating button.

### 2.5. Error Handling & Retry
*   Update `ChatMessage` component to render error state.
*   Add "Retry" button for failed messages.
*   Action: `retryMessage(id)` in store -> re-calls `sendMessage` with original content.

## 3. Backend & Reliability

### 3.1. WebSocket Heartbeat
*   **Frontend**: In `useWebSocket`, implement a `setInterval` (30s) to send `{"type": "ping"}`.
*   **Backend**: Ensure `websocket.py` handles "ping" and replies "pong" to keep connection alive at the load balancer/proxy level.

### 3.2. Message Deduplication
*   **Frontend**: Maintain a `Set<string>` of processed message IDs in the store or hook.
*   **Logic**: Before adding a message from WebSocket, check if `id` exists. If it matches an optimistic message (by content or temp ID mapping), merge them.

## 4. Simulation Mode Cleanup
*   **Frontend**: Remove `SimulationMode` toggle.
*   **Backend**: Verify `_execute_shell_command` enforces real execution.
*   **UI**: Rename "Simulation" to "Sandbox" if retained, or remove level 2 entirely if unused.

## 5. Plan of Action

1.  **Dependencies**: Install `react-markdown rehype-highlight remark-gfm`.
2.  **Types**: Update `types.ts`.
3.  **Components**: Create `RichMessage` and `AutoScroll` hook.
4.  **Store**: Refactor `missionStore` for optimistic updates and streaming.
5.  **Integration**: Update `AIChatPanel` to use new components and store logic.
6.  **Backend**: Verify heartbeat and ping/pong.
7.  **Cleanup**: Remove simulation UI artifacts.
