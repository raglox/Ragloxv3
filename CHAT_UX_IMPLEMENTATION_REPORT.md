# RAGLOX Chat UX Improvements - Implementation Report

## Overview
This PR implements the "User Experience TLC" and "State Management Overhaul" for the RAGLOX chat interface, as requested.

## Changes Implemented

### 1. Frontend Experience (TLC)
*   **Rich Markdown Rendering**: Added `RichMessage.tsx` using `react-markdown`, `rehype-highlight`, and `remark-gfm` to render code blocks, tables, and formatted text in chat messages.
*   **Streaming Responses**: Integrated real-time typing indicators and token streaming in `AIChatPanel.tsx` via WebSocket events (`ai_response_start`, `ai_token_chunk`).
*   **Status Indicators**: Added visual states for messages: Sending (spinner), Sent (check), Streaming (pulse), and Error (alert).
*   **Optimistic Updates**: Messages appear immediately in the UI as "Sending" before the API confirms.
*   **Auto-Scroll**: Implemented `useAutoScroll` hook to keep the chat view at the bottom during streaming, with a "New messages" floating button if the user scrolls up.

### 2. Reliability & State
*   **WebSocket Heartbeat**: Added a 30s ping/pong heartbeat in `useWebSocket.ts` to maintain connections through load balancers/proxies.
*   **Message Deduplication**: Implemented a `processedMessageIds` Set in `missionStore.ts` and `useWebSocket.ts` to prevent duplicate messages when reconnecting or receiving both HTTP and WS responses.
*   **Error Handling**: Added retry logic and inline error messages for failed chat actions.

### 3. Simulation -> Sandbox
*   **Rebranding**: Renamed "Simulation Mode" to "Sandbox Mode" in `CapabilityIndicator.tsx` to clearly communicate that commands run in a safe, isolated environment (or mock mode) when real VMs are not yet ready.
*   **Clarification**: Updated tooltips to explain that Sandbox output is representative but not from live external targets.

## Files Modified
*   `webapp/frontend/client/src/components/manus/AIChatPanel.tsx`: Major refactor to merge "Manus" design with new features.
*   `webapp/frontend/client/src/components/chat/RichMessage.tsx`: New component.
*   `webapp/frontend/client/src/hooks/useWebSocket.ts`: Added heartbeat and deduplication.
*   `webapp/frontend/client/src/stores/missionStore.ts`: Added deduplication logic and improved state handling.
*   `webapp/frontend/client/src/components/manus/CapabilityIndicator.tsx`: Simulation -> Sandbox.
*   `webapp/frontend/client/src/hooks/useAutoScroll.ts`: New hook.

## Verification
*   **Type Check**: Passed `tsc --noEmit` (ignoring unrelated errors in other files).
*   **Dependencies**: Validated `react-markdown` installation.

## Next Steps
*   Deploy and verify visually that the typing indicator works smoothly with the backend streaming.
*   Test the "Sandbox" mode transition when a real VM becomes ready.
