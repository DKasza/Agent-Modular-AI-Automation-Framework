# Agent – Modular AI Automation Framework

_A fully asynchronous, modular AI agent framework with CLI and WebUI support._

---

## 🚀 Overview

The **Agent** framework is designed for **enterprise-grade AI automation**, enabling developers and operators to integrate **Large Language Models (LLMs)** with tool execution, long-term memory, real-time monitoring, and a robust security layer.

**Key capabilities:**
- Natural language command parsing (LLM-driven)
- Fully asynchronous (Python `asyncio`)
- Modular **Tool** and **Plugin** system
- Advanced **Memory Management** (STM/LTM + Vector Store)
- Integrated telemetry (Prometheus, WebSocket streaming)
- Role-based security policies
- CLI and WebUI support

---

## 🧩 Core Architecture

The Agent follows a **layered, component-driven architecture**:

1. **Core Layer**
   - **Component Registry** – central component container
   - **Lifecycle Manager** – initialization, runtime, and shutdown orchestration
   - **Event Bus** – async pub/sub for decoupled communication
   - **Hooks** – pluggable callbacks for custom behavior

2. **Manager Layer**
   - **Tool Manager** – routes parsed commands to tools
   - **Plugin Manager** – dynamically loads/unloads plugins
   - **Memory Manager** – retains conversational and operational context
   - **Session Manager** – handles multi-session isolation

3. **Execution Layer**
   - **Tools** – isolated, functional modules
   - **Plugins** – custom feature extensions

4. **Integration Layer**
   - **Telemetry Exporter** – Prometheus, WebSocket
   - **LLM Adapter** – interfaces with selected LLM backends
   - **Security Policy** – enforces RBAC and operation filtering

---

## 🔧 Core Managers

### Tool Manager
Responsible for routing commands to the correct tool:
- Registers tools at startup
- Matches parsed command metadata to tool capabilities
- Enforces security policies before execution
- Logs results to telemetry and emits relevant events

---

### Plugin Manager
- Loads class-based or function-based plugins from the `plugins/` directory
- Supports hot reloading for development
- Plugins can hook into events, modify commands, or add tools

---

### Session Manager
- Handles multiple concurrent sessions
- Persists and restores context per session
- Enables isolation between user or task contexts

---

### Memory Manager
The **Memory Manager** retains and retrieves context for coherent, long-lived interactions.

#### Features:
- **Short-Term Memory (STM)** – recent conversation turns
- **Long-Term Memory (LTM)** – persistent store with semantic vector search
- **Session Isolation** – scoped recall to current or cross sessions
- **Summarization** – compact history for token efficiency
- **Vector Store Integration** – semantic retrieval using embeddings

#### Workflow:
1. On insert: store entry in STM buffer + queue for LTM flush
2. Periodic flush to SQLite + vector index
3. On retrieval: combine STM recency + LTM top-k vector results
4. Apply token budget and security filtering before prompt assembly

#### Background Tasks:
- Async flush loop
- Vector index synchronization
- Optional maintenance (checkpoints, cleanup)

---

## 🛠 Tools

### FileTool
Handles file system–related commands:

**Capabilities:**
- List files and directories
- Copy, move, rename, delete files/folders
- Search files by name or pattern
- Compress (ZIP) and extract archives
- Real-time file system monitoring via directory watchers

**Safety:**
- Path resolution uses cached indexes if full paths are not provided
- Security Policy checks before destructive actions
- Async, non-blocking I/O operations

---

### SystemTool
Provides access to system-level information and controls:

**Capabilities:**
- Retrieve system metrics (CPU, memory, disk usage)
- Get OS and environment details
- Manage device state (e.g., reboot, shutdown) if allowed
- Process-level operations (if enabled)

**Safety:**
- Restricts critical operations to authorized roles
- Integrates with telemetry for system health reporting

---

## 📊 Telemetry & Monitoring

**Data collected:**
- Command execution logs
- Tool and system events
- Performance metrics (CPU, memory, disk, latency)

**Integrations:**
- **Prometheus Exporter** – exposes `/metrics` endpoint
- **WebSocket Stream** – sends real-time telemetry updates to UI

---

## 🔒 Security & Policy

- **Role-Based Access Control (RBAC)**
- **Operation Filtering** – allow/deny before execution
- **Audit Logging** – records all denied/restricted operations

Security rules are applied centrally in the Tool Manager before any command reaches its tool.

---

## 🔌 Extensibility & Plugin System

**Plugin types:**
- **Class-based** – extend `BasePlugin` to access lifecycle and events
- **Function-based** – export a `register()` hook to attach to the system

**Hot Reloading:**
- Watches plugin files and reloads them without agent restart

---

## 🗂 FileTool – Unified File Management Tool

_The FileTool is a modular, parser-driven file management component of the Agent framework._

---

### 🔍 Core Purpose

The **FileTool** serves as the **central entry point** for all file system–related commands, providing:

- **Safe, asynchronous execution** of file operations
- **Flexible command parsing** for CLI, WebUI, and LLM input
- **Integration** with:
  - Indexed path search (`SQLitePathCache`)
  - Real-time file system monitoring (`DirectoryWatcher`)
  - LLM context memory storage (`MemoryManager`)

---

### 🔧 Architecture Overview

1. **Command Parsing** (`parser.py`)  
   - Detects **structured JSON** and **natural language** commands  
   - Converts input into `ParsedFileCommand` objects  
   - Maps aliases to canonical operations in `types.py`

2. **Command Execution** (`actions.py`)  
   - Async I/O for file, search, compression, and memory commands  
   - Uses `SQLitePathCache` for **fast path resolution**  
   - Falls back to OS search or direct directory scanning

3. **Path Resolution & Monitoring**  
   - Indexed lookup with `SQLitePathCache`  
   - Real-time updates with `DirectoryWatcher`  
   - Unified resolution strategy with `PathResolver`

---

### 📦 Key Modules

- **`tool.py`** – Orchestrates FileTool lifecycle, integrates cache, watcher, and memory  
- **`parser.py`** – Recognizes CLI and JSON commands, assigns operations  
- **`types.py`** – Defines supported operations (`LIST`, `COPY`, `DELETE`, `REMEMBER`, etc.)  
- **`actions.py`** – Executes commands asynchronously; integrates memory operations  
- **`sqlite_path_cache.py`** – Async SQLite path cache with fuzzy search  
- **`path_indexer.py`** – Scans allowed directories, updates cache in batches  
- **`directory_watcher.py`** – Real-time file system change detection and event publishing  
- **`watcher_health.py`** – Monitors watcher state and last event  
- **`path_resolver.py`** – Combines multiple lookup sources for best match

---

### 🧠 Memory-Integrated Commands

- **`remember <text>`** – Store text in MemoryManager  
- **`recall <query>`** – Retrieve top relevant stored entries  
- **`forget <query>`** – Delete a specific memory entry  

---

### 🔒 Safety & Security

- Security Policy checks before execution  
- Dry-run mode for safe simulation  
- Blocked system directories excluded from indexing  
- Path resolution ensures correct targets only  

---

### 📊 Telemetry Integration

Publishes **EventBus** events:
- `tool.file.action`  
- `tool.file.result`  
- `tool.file.error`

Usable by UI, logging, and monitoring dashboards.

---

### 🔄 Example – CLI Command

1. **Parse** → `Operation.COPY`, `target="report.docx"`, `destination="D:/Archive"`  
2. **Resolve Path** → Located in indexed cache  
3. **Execute** → File copied asynchronously  
4. **Result** → `{ "status": "ok", "result": "📄 Copied: ..." }`

---

### 🔄 Example – LLM JSON Command

```json
{
  "operation": "search",
  "target": "project_plan",
  "options": { "recursive": true }
}
```
## 🧠 Memory Manager – Short-Term & Long-Term Context Storage

_The Memory Manager is responsible for storing, retrieving, and managing both short-term and long-term context for the Agent, enabling coherent multi-turn interactions and persistent knowledge._

---

### 🔍 Core Purpose

The **Memory Manager** provides:

- **Short-Term Memory (STM)** – recent conversation turns and events for contextual replies.
- **Long-Term Memory (LTM)** – persistent storage of facts, actions, and context with semantic vector search.
- **Session Management** – separate, named conversational contexts.
- **Background Processing** – automatic flush, vector indexing, and session markers.
- **Context Building** – integrates with `context_builder.py` to assemble prompts from STM, LTM, and summaries.
- **Metrics & Telemetry** – usage tracking for UI panels and monitoring.

---

### 🔧 Architecture Overview

1. **Persistent Storage**  
   - SQLite database for raw memory records (`memories` table).  
   - Indexed columns for fast retrieval by time, type, role, or session.  

2. **Vector Search Layer**  
   - `VectorMemory` for semantic similarity search.  
   - Uses **OpenAI embeddings** if configured (`EmbeddingClient`), with fallback hash embeddings.  

3. **Session Isolation**  
   - Each memory entry is tagged with a `session_id`.  
   - Automatic insertion of **session start markers** with generated titles.

4. **Background Loops**  
   - **Flush loop** – periodically writes buffered STM entries to LTM + vector index.  
   - **STM GC loop** – placeholder for short-term cleanup (currently no deletion).

5. **Context Building** (`context_builder.py`)  
   - **Warm-up**: Loads recent history into STM and summarizes older content.
   - **STM Sync**: Fetches new messages since last update.
   - **LTM Augmentation**: Adds relevant long-term context if the user’s query implies historical references.
   - **Prompt Assembly**: Combines STM, LTM, and the current user input into a token-efficient prompt.

---

### 📦 Key Modules

- **`memory_manager.py`** – Main controller for STM/LTM, sessions, and flush loops.
- **`context_builder.py`** – Builds conversational context from memory for LLM prompts.
- **`vector_memory.py`** – Persistent vector store with cosine similarity search.
- **`vector_store.py`** – Core vector storage engine (in-memory & SQLite backends).
- **`embedding_client.py`** – Handles embedding generation via OpenAI API or fallback.

---

### 🗂 Data Model

| Field         | Purpose                          | Example                           |
|---------------|----------------------------------|-----------------------------------|
| `id`          | Unique record identifier         | UUID                              |
| `text`        | Stored content                   | "User requested file copy…"       |
| `metadata`    | Structured metadata              | `{ "role": "user", "type": "chat_log" }` |
| `type`        | Logical category                 | `chat_log`, `system`, etc.        |
| `role`        | Origin of entry                  | `user`, `assistant`, `tool`       |
| `session_id`  | Session identifier               | `f81d4fae-7dec-11d0-a765…`        |
| `ts`          | Timestamp (epoch)                | `1731234567.123`                  |

---

### 🧮 Core Operations

- **`insert(text, metadata, session_id)`** – Adds an entry to STM buffer; triggers flush if thresholds met.  
- **`flush()`** – Writes STM buffer to SQLite and updates vector index.  
- **`search_long_term(query, top_k)`** – Retrieves top-K similar entries from vector memory.  
- **`list_sessions()`** – Lists known sessions with titles and last activity timestamps.  
- **`create_session()`** – Starts a new session and inserts a session marker.  
- **`delete_session(session_id)`** – Removes all records for a session.  
- **`get_session_messages(session_id)`** – Returns full session history.  
- **`update_session_title(session_id, title)`** – Updates the title of a session.
- **`build_contextual_prompt(...)`** – Generates a token-optimized context for LLMs, mixing STM, LTM, and summaries.

---

### 🧠 Short-Term vs Long-Term Memory

- **STM**  
  - Stored in memory buffer until flushed.  
  - Designed for immediate recall of recent turns.  
  - Managed in-memory via `context_builder` with a maximum history window (`MAX_HISTORY`).

- **LTM**  
  - Stored persistently in SQLite (`memories` + `vectors`).  
  - Searchable via vector similarity.  
  - Retains context across sessions and restarts.  
  - Summaries from old messages are stored in vector memory for efficient recall.

---

### 📊 Metrics & Telemetry

The Memory Manager tracks:

- **STM inserts** count  
- **LTM vector additions** count  
- **Search queries** count  
- **Flush / checkpoint counts**  
- **Last insert, search, flush timestamps**  

These metrics are exposed via `get_usage_metrics()` for dashboards.

---

### 🔒 Safety & Reliability

- **Locking** – Async locks prevent concurrent writes from corrupting state.  
- **Checkpoints** – WAL checkpoints run periodically for DB integrity.  
- **Fallback Embeddings** – If OpenAI embedding fails, a lightweight hash embedding is used.  
- **Session Markers** – Help separate and identify different conversation histories.

---

### 🔄 Example – Context Build Flow

1. **Session Warm-Up** – Loads up to 100k recent messages; summarizes old content if above `SUMMARY_THRESHOLD`.  
2. **Sync STM** – Fetches and appends only new messages since the last update.  
3. **Augment with LTM** – If query implies historical reference, retrieves relevant long-term memories.  
4. **Apply Filters** – Optionally filter by roles or keywords before assembly.  
5. **Assemble Prompt** – Combine LTM (few entries) + STM (recent) + current input into a prompt under the token limit.

---

### 🌐 Example – Session Management

```text
Session A (Project Alpha)
 ├─ User: "Create budget file"
 ├─ Assistant: "File created"
 └─ Tool: "Wrote file budget.xlsx"

Session B (Project Beta)
 ├─ User: "Find meeting notes"
 └─ Assistant: "Found notes_meeting.txt"
```
## 🔒 Security & Access Control – Integrated Security Framework

_The Agent security framework combines role-based access control (RBAC), encrypted user management, multi-factor authentication, password policy enforcement, and tamper-proof audit logging._

---

### 🔍 Core Purpose

The **security subsystem** provides:

- **Role-Based Access Control (RBAC)** – managed by `SecurityPolicy`.
- **User and Profile Management** – encrypted storage with `ProfileManager`.
- **Password Policy Enforcement & Brute Force Protection** – via `PasswordManager`.
- **Multi-Factor Authentication (2FA)** – TOTP with AES-encrypted secrets using `TOTPManager`.
- **Session Management** – HMAC-signed tokens in `AuthService`.
- **Audit Logging** – AES-encrypted, hash-chained logs via `AuditLogger`.

---

### 📦 Key Modules

| Module | Responsibility |
|--------|----------------|
| **`security_policy.py`** | Defines RBAC rules, forbidden paths, critical operations, and policy evaluation logic. |
| **`profile_manager_secure.py`** | Encrypted `.env` and user database management, integrates `SecurityPolicy` and `PasswordManager`. |
| **`password_manager.py`** | Argon2 password hashing, AES-encrypted pepper, brute force lockout with persistent tracking. |
| **`totp_manager.py`** | AES-encrypted TOTP secrets, OTP generation and verification, QR provisioning. |
| **`auth_service_secure.py`** | Unified authentication and authorization service; session tokens, login/logout, 2FA, admin approvals. |
| **`audit_logger.py`** | AES-encrypted, HMAC-linked audit log with file, syslog, or HTTP output modes. |

---

### 🛡 SecurityPolicy Highlights (`security_policy.py`)

- **RBAC Hierarchy**:
  - `guest` → list/search
  - `user` → inherits guest + copy/open
  - `poweruser` → inherits user + move/delete
  - `admin` → inherits poweruser + all (`*`)
- **Path Filtering** – deny access to critical OS paths (`C:\Windows`, `/etc`, `/root`) unless admin.
- **Operation Filtering** – deny dangerous commands (`format`, `shutdown`), require approval for critical ops (`reboot`, `registry_edit`, `network_config`).
- **Audit Hooks** – logs allow/deny decisions via attached `AuditLogger`.

---

### 👤 ProfileManager Highlights (`profile_manager_secure.py`)

- **Encrypted Profiles** – AES-GCM encryption for `.env` configuration and user database.
- **Default Admin** – auto-generated with strong password on first run.
- **User Management** – create, update password, enable/disable 2FA.
- **Policy Integration** – calls `SecurityPolicy.is_allowed()` before allowing non-admin operations.
- **Export Functions** – list all users, roles, and 2FA status.

---

### 🔑 PasswordManager Highlights (`password_manager.py`)

- **Argon2 Hashing** – OWASP-recommended parameters for strong password hashing.
- **AES-Encrypted Pepper** – extra secret stored separately, encrypted at rest.
- **Password Policy** – minimum 12 chars, upper/lowercase, number, special char.
- **Brute Force Lockout** – persistent tracking of failed attempts and timed lockouts.
- **Rehash Detection** – prompts for rehash if parameters change.

---

### 📲 TOTPManager Highlights (`totp_manager.py`)

- **AES-Encrypted Secrets** – secure at rest in `totp_secrets.enc`.
- **Standard Compatibility** – RFC 6238, Google/Microsoft/Authy.
- **Multiple Algorithms** – SHA1, SHA256, SHA512 support.
- **Provisioning** – generate OTPs, provisioning URIs, and QR codes.
- **Validation Window** – 30-second OTP window with ±1 step tolerance.

---

### 🔐 AuthService Highlights (`auth_service_secure.py`)

- **Session Tokens** – HMAC-signed, base64-encoded (JWT not required).
- **Login Flow**:
  - Verify username and password.
  - If 2FA enabled, verify OTP with lockout on repeated failure.
  - Create signed session token with TTL.
- **Admin Approval** – optional OTP confirmation for critical actions.
- **Audit Integration** – every action logged with status (OK/DENY/FAIL).
- **Permission Checks** – calls `SecurityPolicy.is_allowed()` based on role.

---

### 📝 AuditLogger Highlights (`audit_logger.py`)

- **AES-256-GCM Encrypted Logs** – all audit entries encrypted at rest.
- **HMAC-SHA256 Hash Chain** – ensures log integrity and tamper detection.
- **Multiple Output Modes** – file, syslog, HTTP API.
- **Integrity Verification** – validates the hash chain of all entries.
- **Entry Fields**:
  - timestamp, user, action, target, status, details, hash

---

### 🔄 Example – Secure Command Flow

1. **User Login**  
   → Password verified with `PasswordManager`.  
   → If 2FA enabled, OTP validated with `TOTPManager`.  
   → Session token issued by `AuthService`.

2. **Command Execution**  
   → `AuthService.check_permission()` ensures session is valid.  
   → Role permissions checked via `SecurityPolicy`.  
   → If allowed, Tool Manager executes; else, command blocked.

3. **Audit Trail**  
   → All events (login, permission check, action) logged with `AuditLogger`.  
   → Logs are encrypted and integrity-protected.

---

### 📌 Summary

The integrated **Security & Access Control framework** in the Agent ensures:

- Strong authentication with password policy, peppering, and 2FA.
- Fine-grained RBAC with critical operation safeguards.
- Encrypted and integrity-protected audit logs.
- Centralized session and permission management.

This combination provides enterprise-grade security while remaining modular and extendable for different deployment environments.


## 🤖 LLM Integration – Prompt Builder & LLM Adapter

_The Agent integrates with LLMs (e.g., GPT-4o, Mistral) via a flexible adapter and hybrid prompt builder, enabling structured command generation or natural text responses._

---

### 🔍 Core Purpose

The LLM integration layer provides:

- **Structured Command Generation** – Returns strictly valid JSON commands based on a defined schema for tools like `FileTool` and `SystemTool`.
- **Natural Language Responses** – If the user input is conversational, returns plain text instead of JSON.
- **Hybrid Prompt Logic** – Adapts format and rules depending on the type of request.
- **Backend Flexibility** – Works with OpenAI GPT-4o, Mistral, or other API-compatible models.

---

### 🔧 Architecture Overview

1. **Prompt Construction** (`prompt_builder.py`)  
   - Builds system prompts with **dual-mode** behavior:
     - **Command Mode** – Forces JSON output matching the provided schema.
     - **Conversation Mode** – Allows freeform natural text.
   - Injects language constraints (English-only keys).
   - Configurable style, output format, and instruction mode.

2. **LLM Communication** (`llm_adapter.py`)  
   - Wraps LLM API calls with a **unified async interface**.
   - Supports both **string prompts** and **structured messages[]** format.
   - Passes JSON tool schemas to the model for `function_call` responses.
   - Handles both function call outputs and plain text replies.
   - Implements **error handling** and fallback responses.

3. **Utility Support** (`utils.py`)  
   - Normalizes and expands user paths (`~` → home directory).
   - Ensures consistent path format across platforms before sending to tools.

---

### 📦 Key Components

- **`build_prompt(task, output_format, language, style, instruction_mode)`**  
  Builds the complete system + user prompt string, embedding JSON schema rules for command mode.

- **`LLMAdapter`**  
  - **`send(messages)`** – Sends prompt/messages to the LLM API.  
  - **`chat(prompt)`** – Simplified wrapper for single string prompts.  
  - **`is_online()`** – Quick health check for LLM availability.  

- **Schemas**  
  - `file_tool_schema` – JSON schema for file operations.
  - `system_tool_schema` – JSON schema for system operations.

---

### 📊 Response Types

- **Function Call**  
  - Returned when the LLM detects a tool operation.
  - Output includes `name` (tool) and `arguments` (JSON object).
- **Text**  
  - Returned for conversational input or non-command responses.

---

### 🛡 Safety & Constraints

- **Strict Schema Enforcement** – Commands must match the defined JSON schema exactly.
- **No Mixed Formats** – Either JSON object or plain text, never both.
- **Fallback Handling** – Unknown commands return a predefined `{"operation":"unknown",...}` JSON.
- **Error Logging** – All API errors and JSON parse issues are logged.

---

### 🔄 Example – Command Mode

**User:**  

**LLM Response:**  
```json
{
  "operation": "list",
  "target": "C:/Projects",
  "destination": "",
  "options": {}
}

💬 Example – Conversation Mode

User:
Hi, how are you?
LLM Response:
I'm doing well! How can I help you today?
