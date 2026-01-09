# CLAUDE.md: AI Developer Guidelines for Raglox v3

This document provides essential guidelines for AI developers working on the Raglox v3 project. Its purpose is to ensure code quality, maintain a clean architecture, and streamline the development process. All developers, especially those working with AI agents, are expected to follow these guidelines.

**Core Philosophy: The 70/30 Methodology**

We follow a **70/30 methodology** for all development tasks. This means that **70% of your time should be dedicated to analysis, understanding, and planning**, while only **30% should be spent on implementation (writing code)**. This approach is crucial for preventing "spaghetti code" and ensuring that all contributions are well-thought-out and align with the project's architecture.

---

## 1. Project Overview

Raglox v3 is a next-generation cybersecurity platform that automates Red Team operations using an AI-driven, event-based architecture. The system is built around a central **Blackboard** that facilitates communication and data sharing between various specialized AI agents (**Specialists**).

### Key Architectural Concepts

| Concept | Description |
| ------- | ----------- |
| **Blackboard Architecture** | The core of the system is a Redis-based Blackboard. All data, events, and tasks are stored on the Blackboard, which acts as a central hub for communication between components. |
| **Mission Controller** | The `src/controller/mission.py` file contains the central orchestration logic for all missions. It manages the mission lifecycle, coordinates Specialists, and tracks goals. |
| **Specialists** | These are AI agents with specific expertise (e.g., Recon, Attack, Analysis). They operate independently, reacting to data and events on the Blackboard. |
| **Event-Driven** | The system is highly event-driven. Specialists and other components subscribe to events on the Blackboard and react accordingly. This allows for a decoupled and scalable architecture. |
| **Firecracker MicroVMs** | The project is transitioning from a OneProvider VM infrastructure to a custom Firecracker-based microVM system for running security tools and missions. This provides a secure and isolated environment for each mission. |

---

## 2. Conversational Workflow: Human-in-the-Loop (HITL)

**IMPORTANT**: The penetration testing workflow in Raglox v3 is fundamentally **conversational**. The user interacts with the AI agent through a chat interface, and the agent responds with actions, questions, and results. This is not a fire-and-forget system; it is a collaborative process between the human operator and the AI.

### 2.1. Core Interaction Model

The interaction between the user and the AI agent follows this pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│                    User <-> Agent Interaction                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌────────────┐      Chat Messages       ┌────────────────────┐ │
│  │            │ ─────────────────────▶   │                    │ │
│  │    User    │                          │   AI Agent         │ │
│  │ (Frontend) │ ◀─────────────────────   │ (Mission Controller│ │
│  │            │   Responses, Questions,  │  + Specialists)    │ │
│  └────────────┘   Approval Requests      └────────────────────┘ │
│        │                                          │             │
│        │         WebSocket (Real-time)            │             │
│        └──────────────────────────────────────────┘             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2. Key Data Models for Conversational Workflow

Understanding these models is essential for developing the conversational features:

| Model | Location | Purpose |
| ----- | -------- | ------- |
| `ChatMessage` | `src/core/models.py` | Represents a single message in the conversation. Contains `role` (user/system/assistant), `content`, and optional `command`/`output` for terminal integration. |
| `ChatEvent` | `src/core/models.py` | A Blackboard event that is broadcast via WebSocket when a new chat message is created. |
| `ApprovalAction` | `src/core/models.py` | Represents a high-risk action that requires user approval before execution. Contains `action_type`, `risk_level`, `command_preview`, etc. |
| `ApprovalRequestEvent` | `src/core/models.py` | Broadcast via WebSocket to the frontend to display an approval dialog. |
| `ApprovalResponseEvent` | `src/core/models.py` | Broadcast when the user approves or rejects an action. |

### 2.3. Mission Status and HITL

The `MissionStatus` enum includes a `WAITING_FOR_APPROVAL` state. When the AI agent determines that an action is high-risk, it pauses the mission and waits for user approval. The mission will not proceed until the user explicitly approves or rejects the action.

```python
class MissionStatus(str, Enum):
    # ... other statuses
    WAITING_FOR_APPROVAL = "waiting_for_approval"  # HITL: Waiting for user approval
```

### 2.4. Action Types Requiring Approval

The `ActionType` enum defines the types of actions that may require user approval:

| Action Type | Description |
| ----------- | ----------- |
| `EXPLOIT` | Exploitation attempt |
| `WRITE_OPERATION` | File/system writes |
| `LATERAL_MOVEMENT` | Moving to other targets |
| `PRIVILEGE_ESCALATION` | Privilege escalation |
| `DATA_EXFILTRATION` | Data extraction |
| `PERSISTENCE` | Installing persistence |
| `DESTRUCTIVE` | Potentially destructive action |

### 2.5. Risk Levels

The `RiskLevel` enum defines the risk levels for operations:

| Risk Level | Description |
| ---------- | ----------- |
| `LOW` | Low-risk operation, typically does not require approval. |
| `MEDIUM` | Medium-risk operation, may require approval depending on configuration. |
| `HIGH` | High-risk operation, always requires user approval. |
| `CRITICAL` | Critical operation, always requires user approval and may have additional safeguards. |

### 2.6. Key API Endpoints for Conversational Workflow

| Endpoint | Method | Description |
| -------- | ------ | ----------- |
| `/api/v1/missions/{mission_id}/chat` | `POST` | Send a chat message to the mission. |
| `/api/v1/missions/{mission_id}/chat` | `GET` | Get the chat history for a mission. |
| `/api/v1/missions/{mission_id}/approvals` | `GET` | List pending approval requests for a mission. |
| `/api/v1/missions/{mission_id}/approve/{action_id}` | `POST` | Approve a pending action. |
| `/api/v1/missions/{mission_id}/reject/{action_id}` | `POST` | Reject a pending action. |

### 2.7. WebSocket Events

The system uses WebSocket for real-time communication. Key events include:

| Event | Description |
| ----- | ----------- |
| `chat_message` | A new chat message has been sent or received. |
| `approval_request` | The AI agent is requesting approval for a high-risk action. |
| `approval_response` | The user has responded to an approval request. |
| `task_update` | A task has been updated (e.g., started, completed, failed). |
| `mission_update` | The mission status has changed. |

### 2.8. Development Guidelines for Conversational Features

When developing or modifying the conversational workflow, keep the following in mind:

1.  **User is Always in Control**: The user should always have the ability to pause, resume, or stop the mission. High-risk actions should always require explicit approval.
2.  **Clear Communication**: The AI agent should clearly communicate its intentions, findings, and questions to the user. Avoid jargon and be concise.
3.  **Context Awareness**: The AI agent should maintain context across the conversation. It should remember previous messages and actions.
4.  **Error Handling**: If an action fails, the AI agent should inform the user and suggest alternatives.
5.  **Audit Trail**: All chat messages and approval decisions should be logged for auditing purposes. The `ApprovalStore` (`src/core/approval_store.py`) handles this.

---

## 3. Development Environment Setup

For a detailed guide on setting up the development environment, please refer to the `README.md` file. The key steps are:

1.  **Install Prerequisites**: Docker, Docker Compose, Python 3.11+, and `pnpm`.
2.  **Clone the Repository**: `git clone https://github.com/raglox/Ragloxv3.git`
3.  **Set up Infrastructure**: Use Docker Compose to start the Redis, PostgreSQL, and MinIO containers.
4.  **Install Dependencies**: Use `pip install -e ".[dev]"` for the backend and `pnpm install` for the frontend.

---

## 4. Project Structure

A deep understanding of the project structure is essential. Here are the key directories and files:

| Path                      | Description                                                                 |
| ------------------------- | --------------------------------------------------------------------------- |
| `/src`                    | Contains all the backend Python source code.                                |
| `/src/api`                | FastAPI routes for the REST API.                                            |
| `/src/api/routes.py`      | Main API routes, including HITL endpoints for chat and approvals.           |
| `/src/api/websocket.py`   | WebSocket handler for real-time communication.                              |
| `/src/core`               | Core components of the Blackboard architecture, data models, and configuration. |
| `/src/core/models.py`     | Pydantic data models, including `ChatMessage`, `ApprovalAction`, etc.       |
| `/src/core/approval_store.py` | Persistent storage for HITL approval actions and chat history.          |
| `/src/controller`         | The Mission Controller and other orchestration logic.                       |
| `/src/controller/mission.py` | Central mission orchestration, including HITL methods like `send_chat_message`, `request_approval`. |
| `/src/infrastructure`     | Code for interacting with external infrastructure (e.g., Firecracker, SSH). |
| `/src/specialists`        | The AI Specialist agents.                                                   |
| `/webapp`                 | The React/TypeScript frontend application.                                  |
| `/infrastructure`         | Docker Compose files and configuration for the project's infrastructure.    |
| `/tests`                  | Unit and integration tests.                                                 |
| `pyproject.toml`          | Project configuration and dependencies.                                     |
| `CLAUDE.md`               | **This file.** AI developer guidelines.                                     |

---

## 5. Development Workflow

We follow a structured workflow to ensure code quality and consistency:

1.  **Explore (70%)**: Before writing any code, thoroughly explore the existing codebase to understand the relevant components and patterns. Read the related files, understand the data flow, and identify potential impacts.
2.  **Plan (Part of 70%)**: Use the "think" process to create a detailed plan for your changes. This should include the files you will modify, the new functions or classes you will create, and the tests you will add.
3.  **Execute (30%)**: Implement your changes according to your plan. Adhere to the code style and conventions outlined in this document.
4.  **Test**: Write and run tests for your changes. Ensure that all tests pass before submitting your code for review.
5.  **Commit and Pull Request**: Follow the Git and PR etiquette guidelines when committing your code and creating a pull request.

---

## 6. Code Style and Conventions

*   **Python**: We use `black` for code formatting and `flake8` for linting. All code must be compliant with these tools.
*   **TypeScript**: We use `prettier` for code formatting and `eslint` for linting.
*   **Naming Conventions**: Follow standard Python and TypeScript naming conventions (e.g., `snake_case` for functions and variables, `PascalCase` for classes).
*   **Comments and Docstrings**: Write clear and concise comments and docstrings for all code. Explain the "why" not just the "what".

---

## 7. Testing

*   **Unit Tests**: All new code should be accompanied by unit tests. Place unit tests in the `tests` directory, mirroring the structure of the `src` directory.
*   **Integration Tests**: Write integration tests for complex workflows and interactions between components.
*   **Running Tests**: Use the `pytest` command to run the test suite. Refer to the `README.md` for more detailed instructions.

---

## 8. Infrastructure and Deployment

*   **Firecracker Integration**: The `src/infrastructure/cloud_provider/firecracker_client.py` file contains the client for interacting with the Firecracker API. The `src/infrastructure/cloud_provider/vm_manager.py` is being transitioned to use this client.
*   **Deployment**: The `raglox_deployment_guide.md` file provides detailed instructions for deploying the application to the bare metal server.

---

## 9. Common Commands

| Command | Description |
| ------- | ----------- |
| `python -m src.api.main` | Run Backend Server |
| `cd webapp && pnpm dev` | Run Frontend Server |
| `pytest` | Run All Tests |
| `flake8 .` | Run Python Linter |
| `cd webapp && pnpm lint` | Run Frontend Linter |

---

## 10. Security Considerations

*   **Input Validation**: Always validate and sanitize all user input to prevent injection attacks.
*   **Secrets Management**: Use the `.env` files for managing secrets. Do not commit secrets to the repository.
*   **Dependencies**: Keep all dependencies up to date to avoid vulnerabilities.
*   **HITL for High-Risk Actions**: Always use the HITL approval mechanism for high-risk actions. Never execute destructive or sensitive operations without explicit user consent.

---

## 11. Git and PR Etiquette

*   **Branch Naming**: Use a descriptive branch name (e.g., `feature/new-specialist`, `bugfix/mission-controller-error`).
*   **Commit Messages**: Write clear and concise commit messages that explain the changes you have made.
*   **Pull Requests**: Create a pull request with a detailed description of your changes. Reference any relevant issues or tickets.

---

## 12. Next Development Phase: Agent Behavior and Workflow

The next phase of development will focus on refining the behavior of the AI agents (Specialists) and the overall penetration testing workflow. Key areas include:

1.  **LLM Integration**: Enhancing the AI agents' decision-making capabilities using Large Language Models.
2.  **Workflow Orchestration**: Improving the `WorkflowOrchestrator` (`src/core/workflow_orchestrator.py`) to handle complex, multi-step attack scenarios.
3.  **Conversational Refinement**: Making the chat interaction more natural and informative.
4.  **Approval Logic**: Fine-tuning the logic for determining which actions require approval and at what risk level.
5.  **Specialist Coordination**: Improving how Specialists communicate and coordinate their actions via the Blackboard.

When working on these features, always refer back to the core principles outlined in this document, especially the 70/30 methodology and the importance of the conversational, human-in-the-loop workflow.
