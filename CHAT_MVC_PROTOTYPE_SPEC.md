# RAGLOX v3.0 - Minimal Viable Chat (MVC) Prototype Specification
## Clearer Capability Boundaries, Improved Prompts, Sample Transcripts

**Version:** 1.0  
**Document Date:** 2026-01-08

---

## 1. Overview

This specification defines a Minimal Viable Chat (MVC) prototype that addresses the most critical UX gaps while establishing clear capability boundaries. The goal is to create a chat experience that is honest about its limitations while maximizing value within those constraints.

---

## 2. Core Design Principles

### 2.1 Transparency First
- Always communicate the current execution mode
- Never promise capabilities that aren't available
- Proactively explain limitations

### 2.2 Graceful Degradation
- Work fully offline in simulation mode
- Progressively enhance as capabilities become available
- Clear indicators for each capability level

### 2.3 Security by Default
- Dangerous operations require explicit approval
- All commands validated before execution
- Audit trail for all actions

---

## 3. Capability Boundaries

### 3.1 Capability Levels

| Level | Name | Description | Requirements |
|-------|------|-------------|--------------|
| 0 | Offline | UI only, no backend | None |
| 1 | Connected | Chat + API access | Backend running |
| 2 | Simulation | Commands run in simulation | Mission created |
| 3 | Real Execution | Commands run on actual VM | VM provisioned + SSH |

### 3.2 Capability Matrix

| Feature | Level 0 | Level 1 | Level 2 | Level 3 |
|---------|---------|---------|---------|---------|
| View chat history | - | Yes | Yes | Yes |
| Send messages | - | Yes | Yes | Yes |
| Get AI responses | - | Yes | Yes | Yes |
| Run commands | - | - | Simulated | Real |
| View targets | - | - | Yes | Yes |
| Exploit vulns | - | - | Simulated | Real |
| Establish shells | - | - | - | Yes |

### 3.3 Capability Indicators (UI)

```
┌─────────────────────────────────────────┐
│ RAGLOX 3.0              [Level 2: Sim] │
│                         ○ ○ ● ○        │
└─────────────────────────────────────────┘

Legend:
- Level 0: All hollow ○ ○ ○ ○
- Level 1: First filled ● ○ ○ ○  
- Level 2: Two filled ● ● ○ ○
- Level 3: Three filled ● ● ● ○
- Level 4+: All filled ● ● ● ●
```

---

## 4. Improved Prompt System

### 4.1 System Prompt Template

```
You are RAGLOX, an AI-powered Red Team Automation assistant.

CURRENT CONTEXT:
- Mission: {mission_name}
- Status: {mission_status}
- Capability Level: {capability_level} ({capability_description})
- Targets: {target_count}
- Vulnerabilities: {vuln_count}
- Active Sessions: {session_count}

CAPABILITY CONSTRAINTS:
{capability_constraints}

YOUR RESPONSIBILITIES:
1. Help operators understand mission status
2. Execute commands within your capability level
3. Provide security guidance and recommendations
4. Request approval for high-risk actions
5. Be transparent about limitations

COMMAND EXECUTION RULES:
- Level 2 (Simulation): Prefix output with [SIMULATION]
- Level 3 (Real): Execute actual commands with confirmation
- Always validate commands for safety
- Never execute without user intent confirmation for destructive ops

COMMUNICATION STYLE:
- Professional and concise
- Technical accuracy is paramount
- Acknowledge uncertainty when present
- Use markdown formatting for readability
```

### 4.2 Dynamic Constraint Injection

**Level 2 Constraints:**
```
- Commands execute in SIMULATION mode
- Output is representative but not from live systems
- To enable real execution: Complete VM provisioning
- VM Status: {vm_status}
- Estimated time to VM ready: {vm_eta}
```

**Level 3 Constraints:**
```
- Commands execute on LIVE target environment
- All actions are logged and auditable
- High-risk actions require explicit approval
- Session timeout: {session_timeout}
```

### 4.3 Intent-Specific Prompts

**Shell Access Intent:**
```
User wants: Shell access
Capability Level: {level}

If Level < 3:
  Explain current limitations
  Show path to Level 3
  Offer simulation alternative

If Level >= 3:
  Provide shell access options
  Explain safety constraints
  Offer quick commands
```

**Command Execution Intent:**
```
User wants: Execute "{command}"
Capability Level: {level}

Validation steps:
1. Check command against deny list
2. Assess risk level (low/medium/high/critical)
3. If high/critical: Request approval
4. Execute and return results
5. Log action for audit
```

---

## 5. Sample Transcripts

### 5.1 Scenario: New User, Level 1

```
┌────────────────────────────────────────────────────────────┐
│ RAGLOX 3.0                                 [Level 1: API] │
│                                            ● ○ ○ ○        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ 🤖 RAGLOX                                             │  │
│ │                                                       │  │
│ │ Welcome to RAGLOX v3.0! I'm your AI-powered red team │  │
│ │ assistant.                                            │  │
│ │                                                       │  │
│ │ **Current Status:**                                   │  │
│ │ - Connected to backend ✓                              │  │
│ │ - No active mission                                   │  │
│ │ - Capability Level: 1 (API Only)                      │  │
│ │                                                       │  │
│ │ **To get started:**                                   │  │
│ │ 1. Create a new mission with targets                  │  │
│ │ 2. Your execution environment will be provisioned     │  │
│ │ 3. Start reconnaissance on your targets               │  │
│ │                                                       │  │
│ │ What would you like to do?                            │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ You                                                   │  │
│ │                                                       │  │
│ │ I want to scan 192.168.1.0/24                        │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ 🤖 RAGLOX                                             │  │
│ │                                                       │  │
│ │ I'd be happy to help you scan that network!          │  │
│ │                                                       │  │
│ │ **Before we can scan:**                               │  │
│ │ We need to create a mission first. This will:        │  │
│ │ - Define your target scope                            │  │
│ │ - Set up your execution environment                   │  │
│ │ - Enable command execution capabilities               │  │
│ │                                                       │  │
│ │ **Quick Setup:**                                      │  │
│ │ ```                                                   │  │
│ │ Mission Name: Internal Network Scan                   │  │
│ │ Scope: 192.168.1.0/24                                 │  │
│ │ Goals: reconnaissance                                 │  │
│ │ ```                                                   │  │
│ │                                                       │  │
│ │ [ Create Mission ] [ Customize ]                      │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

### 5.2 Scenario: Mission Active, Level 2 (Simulation)

```
┌────────────────────────────────────────────────────────────┐
│ RAGLOX 3.0                                 [Level 2: Sim] │
│ Mission: mark loma                         ● ● ○ ○        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ You                                                   │  │
│ │                                                       │  │
│ │ run nmap -sV 172.245.232.188                         │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ 🤖 RAGLOX                                             │  │
│ │                                                       │  │
│ │ **⚠️ Running in SIMULATION Mode**                     │  │
│ │                                                       │  │
│ │ Your execution environment is being prepared.        │  │
│ │ Progress: ████░░░░░░ 40% (~3 minutes remaining)       │  │
│ │                                                       │  │
│ │ **Simulated Output:**                                 │  │
│ │ ```                                                   │  │
│ │ [SIMULATION] $ nmap -sV 172.245.232.188              │  │
│ │                                                       │  │
│ │ Starting Nmap 7.94 ( https://nmap.org )              │  │
│ │ Nmap scan report for 172.245.232.188                 │  │
│ │ Host is up (0.0010s latency).                        │  │
│ │                                                       │  │
│ │ PORT     STATE SERVICE    VERSION                    │  │
│ │ 22/tcp   open  ssh        OpenSSH 8.4p1              │  │
│ │ 80/tcp   open  http       nginx 1.18.0               │  │
│ │ 443/tcp  open  https      nginx 1.18.0               │  │
│ │                                                       │  │
│ │ [SIMULATION] Results are representative only         │  │
│ │ ```                                                   │  │
│ │                                                       │  │
│ │ **Real execution will be available when your VM is** │  │
│ │ **ready.** I'll notify you when it's complete.       │  │
│ │                                                       │  │
│ │ [ Notify Me ] [ Continue in Simulation ]              │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

### 5.3 Scenario: Full Capability, Level 3 (Real Execution)

```
┌────────────────────────────────────────────────────────────┐
│ RAGLOX 3.0                                [Level 3: Real] │
│ Mission: mark loma                         ● ● ● ○        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ You                                                   │  │
│ │                                                       │  │
│ │ run nmap -sV 172.245.232.188                         │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ 🤖 RAGLOX                                             │  │
│ │                                                       │  │
│ │ **✅ Executing on Live Environment**                  │  │
│ │ VM: raglox-user-a33cb761 | IP: 10.0.0.5              │  │
│ │                                                       │  │
│ │ ```bash                                               │  │
│ │ ubuntu@raglox:~$ nmap -sV 172.245.232.188            │  │
│ │                                                       │  │
│ │ Starting Nmap 7.94 ( https://nmap.org )              │  │
│ │ Nmap scan report for 172.245.232.188                 │  │
│ │ Host is up (0.023s latency).                         │  │
│ │                                                       │  │
│ │ PORT     STATE SERVICE    VERSION                    │  │
│ │ 22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu       │  │
│ │ 80/tcp   open  http       nginx 1.18.0 (Ubuntu)      │  │
│ │ 443/tcp  open  ssl/http   nginx 1.18.0               │  │
│ │ 3306/tcp open  mysql      MySQL 8.0.32               │  │
│ │                                                       │  │
│ │ Service detection performed. Exit code: 0            │  │
│ │ ```                                                   │  │
│ │                                                       │  │
│ │ **Findings:**                                         │  │
│ │ - 4 open ports discovered                             │  │
│ │ - MySQL exposed (potential risk)                      │  │
│ │ - Services identified with versions                   │  │
│ │                                                       │  │
│ │ **Suggested Next Steps:**                             │  │
│ │ 1. Check MySQL for default credentials               │  │
│ │ 2. Scan for web vulnerabilities on port 80/443       │  │
│ │ 3. Check SSH for weak authentication                 │  │
│ │                                                       │  │
│ │ [ Scan MySQL ] [ Web Vuln Scan ] [ SSH Audit ]       │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

### 5.4 Scenario: High-Risk Action Requiring Approval

```
┌────────────────────────────────────────────────────────────┐
│ RAGLOX 3.0                                [Level 3: Real] │
│ Mission: mark loma                         ● ● ● ○        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ You                                                   │  │
│ │                                                       │  │
│ │ exploit the mysql vulnerability                       │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ 🤖 RAGLOX                                             │  │
│ │                                                       │  │
│ │ **🔐 Approval Required**                              │  │
│ │                                                       │  │
│ │ This action requires your explicit approval because  │  │
│ │ it could modify the target system.                   │  │
│ │                                                       │  │
│ │ ┌────────────────────────────────────────────────┐   │  │
│ │ │ **Proposed Action**                             │   │  │
│ │ │                                                 │   │  │
│ │ │ Type: Exploit Execution                         │   │  │
│ │ │ Target: 172.245.232.188:3306 (MySQL)           │   │  │
│ │ │ Module: auxiliary/scanner/mysql/mysql_login    │   │  │
│ │ │                                                 │   │  │
│ │ │ **Risk Assessment**                             │   │  │
│ │ │ Risk Level: ⚠️ HIGH                             │   │  │
│ │ │ Reasons:                                        │   │  │
│ │ │ - May lock out legitimate users                 │   │  │
│ │ │ - Could trigger security alerts                 │   │  │
│ │ │ - Logs will be generated on target              │   │  │
│ │ │                                                 │   │  │
│ │ │ **Command Preview**                             │   │  │
│ │ │ ```                                             │   │  │
│ │ │ msfconsole -q -x "use auxiliary/scanner/       │   │  │
│ │ │ mysql/mysql_login; set RHOSTS 172.245.232.188; │   │  │
│ │ │ set USERNAME root; run"                        │   │  │
│ │ │ ```                                             │   │  │
│ │ │                                                 │   │  │
│ │ │ [ ✅ Approve ] [ ❌ Reject ] [ 💬 Ask Question ]│   │  │
│ │ └────────────────────────────────────────────────┘   │  │
│ │                                                       │  │
│ │ **Note:** This action will be logged in the audit    │  │
│ │ trail with your approval timestamp.                  │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

### 5.5 Scenario: Error Handling with Clear Feedback

```
┌────────────────────────────────────────────────────────────┐
│ RAGLOX 3.0                                [Level 3: Real] │
│ Mission: mark loma                         ● ● ● ○        │
├────────────────────────────────────────────────────────────┤
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ You                                                   │  │
│ │                                                       │  │
│ │ run ping 172.245.232.188                             │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
│ ┌──────────────────────────────────────────────────────┐  │
│ │ 🤖 RAGLOX                                             │  │
│ │                                                       │  │
│ │ **❌ Command Failed**                                  │  │
│ │                                                       │  │
│ │ ```                                                   │  │
│ │ ubuntu@raglox:~$ ping 172.245.232.188                │  │
│ │ ping: socket: Operation not permitted                │  │
│ │ Exit code: 1                                          │  │
│ │ ```                                                   │  │
│ │                                                       │  │
│ │ **Why this happened:**                                │  │
│ │ Raw socket operations (like ICMP ping) require       │  │
│ │ elevated privileges that aren't available in the     │  │
│ │ sandboxed execution environment.                     │  │
│ │                                                       │  │
│ │ **Alternatives:**                                     │  │
│ │ 1. Use `nmap -sn` for host discovery                 │  │
│ │ 2. Use `curl` to check if web services respond       │  │
│ │ 3. Use `nc -zv` for port-based connectivity test     │  │
│ │                                                       │  │
│ │ **Quick Actions:**                                    │  │
│ │ [ nmap -sn 172.245.232.188 ]                         │  │
│ │ [ curl -I http://172.245.232.188 ]                   │  │
│ │ [ nc -zv 172.245.232.188 22 ]                        │  │
│ └──────────────────────────────────────────────────────┘  │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

---

## 6. Component Specifications

### 6.1 CapabilityIndicator Component

```typescript
interface CapabilityIndicatorProps {
  level: 0 | 1 | 2 | 3;
  vmStatus?: 'not_created' | 'creating' | 'ready' | 'error';
  vmProgress?: number; // 0-100
}

const levelDescriptions = {
  0: 'Offline',
  1: 'API Connected',
  2: 'Simulation Mode',
  3: 'Real Execution'
};

function CapabilityIndicator({ level, vmStatus, vmProgress }: CapabilityIndicatorProps) {
  return (
    <div className="capability-indicator">
      <span className="level-label">[Level {level}: {levelDescriptions[level]}]</span>
      <div className="dots">
        {[0, 1, 2, 3].map(i => (
          <span key={i} className={`dot ${i <= level ? 'filled' : 'empty'}`} />
        ))}
      </div>
      {vmStatus === 'creating' && (
        <div className="vm-progress">
          <progress value={vmProgress} max={100} />
          <span>{vmProgress}%</span>
        </div>
      )}
    </div>
  );
}
```

### 6.2 SimulationBanner Component

```typescript
interface SimulationBannerProps {
  vmStatus: string;
  vmEta?: number; // seconds
  onNotifyMe: () => void;
}

function SimulationBanner({ vmStatus, vmEta, onNotifyMe }: SimulationBannerProps) {
  return (
    <div className="simulation-banner">
      <WarningIcon />
      <div className="content">
        <h4>Running in Simulation Mode</h4>
        <p>
          {vmStatus === 'creating' 
            ? `Your execution environment will be ready in ~${Math.ceil(vmEta / 60)} minutes`
            : 'Create a mission to start real execution'
          }
        </p>
      </div>
      <button onClick={onNotifyMe}>Notify Me</button>
    </div>
  );
}
```

### 6.3 ApprovalCard Component (Enhanced)

```typescript
interface ApprovalCardProps {
  action: ApprovalAction;
  onApprove: (id: string, comment?: string) => void;
  onReject: (id: string, reason: string) => void;
  onAskQuestion: (id: string) => void;
}

function ApprovalCard({ action, onApprove, onReject, onAskQuestion }: ApprovalCardProps) {
  const [showComment, setShowComment] = useState(false);
  const [comment, setComment] = useState('');

  return (
    <div className={`approval-card risk-${action.risk_level}`}>
      <header>
        <LockIcon />
        <h3>Approval Required</h3>
      </header>
      
      <section className="action-details">
        <div className="field">
          <label>Type</label>
          <span>{action.action_type}</span>
        </div>
        <div className="field">
          <label>Target</label>
          <span>{action.target_ip}</span>
        </div>
        <div className="field">
          <label>Risk Level</label>
          <RiskBadge level={action.risk_level} />
        </div>
      </section>

      <section className="risk-reasons">
        <h4>Risk Factors</h4>
        <ul>
          {action.risk_reasons.map((reason, i) => (
            <li key={i}>{reason}</li>
          ))}
        </ul>
      </section>

      <section className="command-preview">
        <h4>Command Preview</h4>
        <pre><code>{action.command_preview}</code></pre>
      </section>

      <footer>
        <button className="approve" onClick={() => onApprove(action.id, comment)}>
          ✅ Approve
        </button>
        <button className="reject" onClick={() => setShowComment(true)}>
          ❌ Reject
        </button>
        <button className="ask" onClick={() => onAskQuestion(action.id)}>
          💬 Ask Question
        </button>
      </footer>

      {showComment && (
        <div className="rejection-form">
          <textarea 
            placeholder="Reason for rejection..."
            value={comment}
            onChange={e => setComment(e.target.value)}
          />
          <button onClick={() => onReject(action.id, comment)}>
            Submit Rejection
          </button>
        </div>
      )}
    </div>
  );
}
```

---

## 7. API Enhancements

### 7.1 New Endpoints

```yaml
# GET /api/v1/system/capability-level
# Returns current capability level for user
Response:
  level: 3
  description: "Real Execution"
  vm_status: "ready"
  vm_ip: "10.0.0.5"
  vm_id: "raglox-user-a33cb761"
  features:
    - shell_access: true
    - command_execution: true
    - exploit_execution: true
    - session_management: true

# GET /api/v1/missions/{id}/execution-mode
# Returns execution mode for specific mission
Response:
  mode: "real"  # or "simulation"
  vm_ready: true
  simulation_reason: null  # or reason string
```

### 7.2 Enhanced Chat Response

```yaml
# POST /api/v1/missions/{id}/chat
Request:
  content: "run nmap -sV 172.245.232.188"

Response:
  id: "msg-123"
  role: "system"
  content: "..."
  execution_mode: "real"  # NEW
  execution_details:      # NEW
    vm_id: "raglox-user-abc"
    vm_ip: "10.0.0.5"
    exit_code: 0
    duration_ms: 5234
  command: "nmap -sV 172.245.232.188"
  output: [...]
  suggestions:           # NEW
    - action: "scan_mysql"
      label: "Scan MySQL"
    - action: "web_vuln_scan"
      label: "Web Vuln Scan"
```

---

## 8. Testing Requirements

### 8.1 Acceptance Criteria

| Scenario | Expected Behavior |
|----------|-------------------|
| Level 0 user sends message | Error with clear instruction to connect |
| Level 1 user runs command | Prompt to create mission |
| Level 2 user runs command | Simulation with clear indicator |
| Level 3 user runs command | Real execution with results |
| Any user runs dangerous command | Approval workflow triggered |
| VM provisioning in progress | Progress indicator shown |
| Command fails | Clear error with alternatives |

### 8.2 Sample Test Cases

```typescript
describe('Chat Capability Levels', () => {
  test('Level 2 shows simulation indicator', async () => {
    const { getByText } = render(<ChatPanel level={2} />);
    await userEvent.type(getByText('input'), 'run ls -la');
    await userEvent.click(getByText('Send'));
    
    expect(getByText('[SIMULATION]')).toBeInTheDocument();
    expect(getByText('Running in Simulation Mode')).toBeInTheDocument();
  });

  test('High-risk command triggers approval', async () => {
    const { getByText } = render(<ChatPanel level={3} />);
    await userEvent.type(getByText('input'), 'exploit mysql');
    await userEvent.click(getByText('Send'));
    
    expect(getByText('Approval Required')).toBeInTheDocument();
    expect(getByText('Risk Level: HIGH')).toBeInTheDocument();
  });
});
```

---

## 9. Implementation Priority

| Priority | Component | Effort | Impact |
|----------|-----------|--------|--------|
| 1 | CapabilityIndicator | Low | High |
| 2 | SimulationBanner | Low | High |
| 3 | Enhanced chat response | Medium | High |
| 4 | ApprovalCard improvements | Medium | Medium |
| 5 | Error handling with alternatives | Medium | High |
| 6 | Proactive suggestions | High | Medium |

---

**Specification End**
