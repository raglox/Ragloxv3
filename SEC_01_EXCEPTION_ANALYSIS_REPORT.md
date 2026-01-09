# SEC-01: except Exception Analysis Report

**Total files scanned:** 137
**Files with except Exception:** 79
**Total except Exception clauses:** 395

## Files by Priority

| # | File | Count | Exceptions Needed |
|---|------|-------|-------------------|
| 1 | `controller/mission.py` | 42 | LLMResponseError, MissionNotFoundError, NotFoundError, +1 more |
| 2 | `api/websocket.py` | 14 | AuthenticationError, RAGLOXException |
| 3 | `api/main.py` | 11 | ConnectionTimeoutError, DatabaseConnectionError, RAGLOXException, +1 more |
| 4 | `core/agent/hacker_agent.py` | 11 | LLMResponseError, RAGLOXException |
| 5 | `core/workflow_orchestrator.py` | 11 | RAGLOXException |
| 6 | `core/token_store.py` | 10 | RAGLOXException |
| 7 | `exploitation/c2/session_manager.py` | 10 | CommandExecutionError, RAGLOXException |
| 8 | `api/security_routes.py` | 9 | InvalidIPAddressError, InvalidUUIDError, RAGLOXException |
| 9 | `api/terminal_routes.py` | 9 | RAGLOXException |
| 10 | `core/llm/local_provider.py` | 9 | AuthenticationError, RAGLOXException |

## Detailed Analysis

### src/controller/mission.py

**Total:** 42 occurrences

**Required exceptions:**
- `LLMResponseError`
- `MissionNotFoundError`
- `NotFoundError`
- `RAGLOXException`

---

### src/api/websocket.py

**Total:** 14 occurrences

**Required exceptions:**
- `AuthenticationError`
- `RAGLOXException`

---

### src/api/main.py

**Total:** 11 occurrences

**Required exceptions:**
- `ConnectionTimeoutError`
- `DatabaseConnectionError`
- `RAGLOXException`
- `RedisConnectionError`

---

### src/core/agent/hacker_agent.py

**Total:** 11 occurrences

**Required exceptions:**
- `LLMResponseError`
- `RAGLOXException`

---

### src/core/workflow_orchestrator.py

**Total:** 11 occurrences

**Required exceptions:**
- `RAGLOXException`

---

### src/core/token_store.py

**Total:** 10 occurrences

**Required exceptions:**
- `RAGLOXException`

---

### src/exploitation/c2/session_manager.py

**Total:** 10 occurrences

**Required exceptions:**
- `CommandExecutionError`
- `RAGLOXException`

---

### src/api/security_routes.py

**Total:** 9 occurrences

**Required exceptions:**
- `InvalidIPAddressError`
- `InvalidUUIDError`
- `RAGLOXException`

---

### src/api/terminal_routes.py

**Total:** 9 occurrences

**Required exceptions:**
- `RAGLOXException`

---

### src/core/llm/local_provider.py

**Total:** 9 occurrences

**Required exceptions:**
- `AuthenticationError`
- `RAGLOXException`

---

