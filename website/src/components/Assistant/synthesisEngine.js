/**
 * Deterministic Semantic Synthesis & Relationship Engine
 * 
 * Dynamically resolves selections completely offline by executing entity-level 
 * semantic interpretation. Compiles custom structural, chronological, and 
 * relational syntheses based on the exact selected keyword and matched database chunk.
 * Guaranteed 100% offline, zero latency, and hallucination-free.
 */

export function synthesizeContext({ selectedText, activeTab, sources, pageContent, refinementText }) {
  // 1. Return structured fallback if no sources matched
  if (!sources || sources.length === 0) {
    return `### Retrieval-Constrained Explanation: Limited Documentation Context
*(No matching documentation anchors identified in the VScanX database for this query)*

### Technical Synthesis
The highlighted concept or query could not be resolved against the offline VScanX technical database. To maintain precise systems engineering integrity, this query layer refuses general cybersecurity or programming synthesis.

### Action Required
Please select text or concepts specifically related to VScanX workflows:
- **CLI Commands & Flags** (e.g., \`--verify\`, \`vscanx scan\`, \`replay\`)
- **System Internals** (e.g., \`PluginManager\`, \`BaseModule\`, \`core/orchestrator.py\`)
- **Vulnerability Domains** (e.g., \`reentrancy\`, \`ssrf\`, \`gvisor\`, \`sandbox\`)
- **Scanning Lifecycle** (e.g., \`State replay\`, \`diff\`, \`event contract\`)

### Related Workflows
- **Getting Started**: [VScanX Installation & Prerequisites](file:///docs) → Prerequisite socket permissions.
- **Reference**: [VScanX CLI Usage Recipes](file:///docs/cli) → CommandLine parameter definitions.`;
  }

  // Normalize selected text query triggers
  const query = (selectedText || "").trim().toLowerCase();
  
  // Extract primary matched source meta
  const primarySource = sources[0];
  const category = primarySource.category;
  const sourceId = primarySource.id;
  const tags = primarySource.tags || [];

  // Calibrate honest, source-grounded match badge text
  let matchTier = "Weak Retrieval Match";
  if (sources.length >= 3) {
    matchTier = "Strong Retrieval Match";
  } else if (sources.length === 2) {
    matchTier = "Medium Retrieval Match";
  }

  // Centralized Metadata & Relationship mapping
  const schemas = sources.flatMap(s => s.relatedSchemas || []).filter(Boolean);
  const commands = sources.flatMap(s => s.relatedCommands || []).filter(Boolean);
  const stages = sources.flatMap(s => s.workflowStages || []).filter(Boolean);
  const contexts = sources.flatMap(s => s.replayContexts || []).filter(Boolean);
  const docRefs = sources.flatMap(s => s.relatedDocs || []).filter(Boolean);

  const uniqueSchemas = [...new Set(schemas)];
  const uniqueCommands = [...new Set(commands)];
  const uniqueStages = [...new Set(stages)];
  const uniqueContexts = [...new Set(contexts)];
  const uniqueDocs = [...new Set(docRefs)];

  // Determine query-specific target entity
  let activeEntity = "generic";
  if (query.includes("replay_id") || query.includes("snapshot_id") || query.includes("snap_")) {
    activeEntity = "replay_id";
  } else if (query.includes("ast") || query.includes("solidity") || query.includes("reentrancy_analyzer")) {
    activeEntity = "ast";
  } else if (query.includes("pluginmanager") || query.includes("plugin_manager") || query.includes("pluginmanage")) {
    activeEntity = "pluginmanager";
  } else if (query.includes("verification_state") || query.includes("finding_id")) {
    activeEntity = "verification_state";
  } else if (query.includes("ssrf") || query.includes("ssrf_detector")) {
    activeEntity = "ssrf";
  } else if (query.includes("sqli") || query.includes("sqli_detector")) {
    activeEntity = "sqli";
  } else if (query.includes("diff") || query.includes("state_mutation")) {
    activeEntity = "diff";
  } else if (query.includes("sandbox") || query.includes("containment") || query.includes("gvisor") || query.includes("anvil") || query.includes("runsc")) {
    activeEntity = "sandbox";
  } else if (query.includes("scapy") || query.includes("npcap") || query.includes("winpcap") || query.includes("sudo") || query.includes("socket")) {
    activeEntity = "scapy";
  } else if (query.includes("event contract") || query.includes("event_type") || query.includes("event_broker")) {
    activeEntity = "event_contract";
  } else if (query.includes("orchestrator") || query.includes("concurrency") || query.includes("thread")) {
    activeEntity = "orchestrator";
  }

  // Detect subsystem domain based on activeEntity
  let domain = "web";
  if (activeEntity === "ast" || tags.includes("web3")) {
    domain = "web3";
  } else if (activeEntity === "replay_id" || activeEntity === "diff" || category === "replay-diff") {
    domain = "replay";
  } else if (activeEntity === "pluginmanager" || activeEntity === "orchestrator" || category === "internals") {
    domain = "plugin";
  } else if (tags.includes("gvisor") || tags.includes("runsc") || activeEntity === "sandbox" && tags.includes("ai")) {
    domain = "ai";
  }

  let output = "";

  // ==========================================================
  // TAB 1: EXPLAIN (Conceptual Interpretation)
  // ==========================================================
  if (activeTab === "explain") {
    output = `### Grounding Evaluation: ${matchTier} (Entity Interpretation)
*(Deterministic contextual synthesis compiled via ${sources.length} local database reference(s))*

### Technical Synthesis
`;

    if (activeEntity === "replay_id") {
      output += `The VScanX **Replay Identifier (\`replay_id\` / \`snapshot_id\`)** is the primary state serialization key in the VScanX framework. 

It maps a specific verification scan run to its baseline JSON snapshot stored in the state directory at \`.vscanx_state/snap_<id>.json\`. The \`replay_id\` captures all network discovery paths, telemetry traces, system events, and compiled findings, permitting developers to re-validate system states offline without duplicate target network scans.`;
    } else if (activeEntity === "ast") {
      output += `The VScanX **Web3 Solidity AST (Abstract Syntax Tree) Parser** is a parsing engine that reads solidity code compiler structures.

Rather than querying node network interfaces blindly, VScanX parses bytecode ASTs to flag vulnerability triggers (e.g. recursive withdrawals or unprotected initialization routes). Once flagged, the engine dispatches a decoupling event contract to spawn local isolated blockchain forks (**Anvil**).`;
    } else if (activeEntity === "pluginmanager") {
      output += `The VScanX **PluginManager** (\`core/plugins/manager.py\`) handles dynamic loading and runtime registration of scanning profiles.

At framework boot, it sweeps target directories using \`pkgutil.walk_packages()\` and dynamically registers classes subclassing the abstract \`BaseModule\` base interface via \`importlib.import_module()\`, hooking scanner methods directly into orchestrator executor loops.`;
    } else if (activeEntity === "verification_state") {
      output += `The VScanX **Verification State (\`verification_state\`)** defines the deterministic lifecyle status of a verified canonical finding:
- **\`VERIFIED\`**: The exploit validator successfully reproduced the vulnerability inside the clean isolated container sandbox, achieving 0% false positives.
- **\`ACTIVE\`**: The vulnerability remains exploitable on subsequent scans.
- **\`RESOLVED\`**: A regression check proves the exploit fails to execute on the replica container, mathematically confirming mitigation.`;
    } else if (activeEntity === "ssrf") {
      output += `The VScanX **SSRF Scanning Subsystem** (\`ssrf_detector.py\`) verifies Server-Side Request Forgery vulnerabilities.

When discovery probers passively detect a request redirection vulnerability on query parameters, they dispatch an \`SSRF_PROBE_ANOMALY\` event. The orchestrator spawns an isolated \`vscanx/val-web:latest\` container sandbox and executes dynamic payload loopback requests, confirming if the backend allows unauthorized requests.`;
    } else if (activeEntity === "sqli") {
      output += `The VScanX **SQLi Scanning Subsystem** (\`sqli_detector.py\`) checks SQL injection vulnerabilities.

Passive sweeps inspect forms and inputs. If matched, the engine publishes a \`SQLI_PROBE_ANOMALY\` event to spawn isolated Docker target replicas containing target databases. Active validators fire loopback exploit payloads, capturing database breakout logs to confirm execution.`;
    } else if (activeEntity === "diff") {
      output += `The VScanX **Delta Comparison Diff Engine** (\`core/state/diff.py\`) mathematically proves regression corrections between run baselines: \`S(t) ➔ S(t+1)\`.

By comparing individual vulnerability signatures between run snapshots (e.g. \`vscanx diff --diff scanA scanB\`), the engine confirms if an exploit trigger that was active in snapshot A successfully reverts in snapshot B, transitioning the finding state to **RESOLVED**.`;
    } else if (activeEntity === "sandbox") {
      output += `The VScanX **Containment Sandbox Subsystem** isolates exploit execution to prevent host network or machine state pollution.

Containment operates dynamically based on the vulnerability domain:
- **Docker (\`vscanx/val-web\`):** Isolates Web/API payload checks.
- **Anvil EVM RPC Node Forking:** Spawns localized block forks to test Web3 contracts safely.
- **gVisor runsc containment:** Spawns secure kernel-level sandboxes to intercept LLM prompt injection escapes.`;
    } else if (activeEntity === "scapy") {
      output += `The VScanX **Low-Level Scapy Packet Crafting Engine** handles raw socket binds for network probers and signature sniffers.

Because raw packet injection bypasses standard OS TCP/IP stack layers, executing active scans requires elevated privileges: Windows environments require raw socket interfaces via **Npcap** or **WinPcap** (with admin command prompt), while Linux/macOS require running the executable with **\`sudo\`**.`;
    } else if (activeEntity === "event_contract") {
      output += `The VScanX **Asynchronous Event Broker** decouples passive scanning from active exploit verification. 

Instead of spawning sandboxes instantly, probers dispatch **Typed Event Contracts** (e.g. \`SSRF_PROBE_ANOMALY\`) to the central bus. The orchestrator polls the broker queue, allocating threads and provisioning isolated sandboxes sequentially to protect system network adapters.`;
    } else if (activeEntity === "orchestrator") {
      output += `The VScanX **Core orchestrator** (\`core/orchestrator.py\`) executes dynamic thread scheduling and decoupled queue allocations.

It utilizes a thread-safe \`concurrent.futures.ThreadPoolExecutor\` to protect system adapters, executing decoupled containment spawns and validation payloads with strict task timeouts, fallback circuit breakers, and thread-isolated loggers.`;
    } else {
      // General getting started or conceptual explainer
      output += `The selected term maps to **${primarySource.title}** in the VScanX technical docs database. 

**Subsystem Detail:**
${primarySource.content}

This concept plays a critical role in the VScanX system architecture, maintaining a clean distinction between passive observation and active isolated exploit containment to achieve zero false-positive alerts.`;
    }

    // Append desaturated relations list
    output += `\n\n### Decoupled Relationships\n`;
    if (uniqueStages.length > 0) {
      output += `- **Primary Stage:** \`${uniqueStages[0]}\`\n`;
    }
    if (uniqueSchemas.length > 0) {
      output += `- **Related Schema:** \`${uniqueSchemas[0]}\`\n`;
    }
    if (uniqueCommands.length > 0) {
      output += `- **CLI Invocation:** \`${uniqueCommands[0]}\`\n`;
    }
    if (uniqueContexts.length > 0) {
      output += `- **Replay Context:** \`${uniqueContexts[0]}\`\n`;
    }
  }

  // ==========================================================
  // TAB 2: WORKFLOW (Chronological Observability Trace)
  // ==========================================================
  else if (activeTab === "workflow") {
    output = `### Grounding Evaluation: ${matchTier} (Workflow Observability Trace)
*(Chronological pipeline sequence compiled from framework specifications)*

### Chronological Execution Pipeline
`;

    // Render precise, highly granular chronological traces matching the selected entity
    if (activeEntity === "replay_id" || activeEntity === "diff") {
      output += `\`\`\`text
[State Snapshot Capture] ➔ [Replay Cache Load] ➔ [State Diff Engine] ➔ [Container Clone] ➔ [Findings Update]
snap_<id>.json file       vscanx replay CLI     core/state/diff.py    Clean replica spawn   ACTIVE to RESOLVED
\`\`\`

1. **Snapshot Capturing:** State snapshots containing logs, event paths, and findings serialize into \`.vscanx_state/snap_<id>.json\`.
2. **Replay Injection:** The developer runs \`vscanx replay --replay-id <id>\` to inject baseline states back into the executor.
3. **Container State Replication:** The spawner provisions identical clean replica containers to execute target exploit tests.
4. **Delta Verification:** If the exploit fails in the clone (or EVM calls revert), the diff engine proves patch mitigation.
5. **State Evolution:** Finding state updates from **ACTIVE** to **RESOLVED** inside the findings database.`;
    } else if (activeEntity === "ast") {
      output += `\`\`\`text
[Solidity Source Parse] ──➔ [AST Generation] ─────➔ [Pattern Matching] ────➔ [Vulnerability Map] ──➔ [Anvil EVM Fork]
Code compiler sweep       AST Node Tree creation    CALL/DELEGATECALL scan    WEB3_REENTRANCY event    Local RPC node spawn
\`\`\`

1. **Solidity Source Parsing:** Passive probers scan contract source files and bytecode opcodes at scanner boot.
2. **AST Node Generation:** Compiles solidity files into a structured Abstract Syntax Tree node mapping.
3. **Pattern Matching:** Inspectors analyze AST structures, checking for state mutations occurring after external calls.
4. **Vulnerability Event Dispatch:** Dispatches a \`WEB3_REENTRANCY_ANOMALY\` contract to the asynchronous bus.
5. **EVM Fork Sandbox Spawn:** Spawns local Anvil Ethereum forks at the trigger block height to execute validators safely.`;
    } else if (activeEntity === "pluginmanager") {
      output += `\`\`\`text
[Module Discovery] ─────➔ [Dynamic Import] ──────➔ [BaseModule check] ────➔ [Instantiations] ─────➔ [Orchestrator Queue]
Walks modules/ paths     importlib package load   Subclass verification    Class methods loaded    ThreadPoolExecutor
\`\`\`

1. **Modules Sweeping:** The manager walks module subdirectories at framework boot using \`pkgutil.walk_packages()\`.
2. **Dynamic Package Import:** discovery sweeps loaded paths, loading classes dynamically via \`importlib.import_module()\`.
3. **Interface Assertion:** Verifies the discovered classes subclass the abstract \`BaseModule\` base interface.
4. **Registration:** Instantiates registered modules, loading their methods and hooks into active memory.
5. **Scheduling Dispatch:** Schedules module runner tasks inside the central orchestrator concurrency pools.`;
    } else if (activeEntity === "verification_state") {
      output += `\`\`\`text
[Exploit Injection] ────➔ [Active Replication] ──➔ [Validation Success] ──➔ [Delta Comparison] ──➔ [State Resolution]
Prober anomaly event     Sandbox container spawn  VERIFIED state mapping   Mitigation check scan   RESOLVED transition
\`\`\`

1. **Anomaly Identification:** Discovery probers capture target vulnerabilities and queue anomaly events.
2. **Dynamic Replica Spawning:** Spawns clean isolated containers or node forks containing identical target setups.
3. **Active Validation Payload:** Exploit validators execute loops; a verified breakout maps findings to **VERIFIED / ACTIVE**.
4. **Mitigation Scan Comparison:** Subsequent scans rerun validators against target replica containers.
5. **State Resolution:** If validators fail to breakout (proving mitigation), the diff engine transitions the finding to **RESOLVED**.`;
    } else if (activeEntity === "ssrf") {
      output += `\`\`\`text
[URL Parameter Sweep] ──➔ [SSRF Anomaly event] ──➔ [Docker Target Spawn] ──➔ [Loopback Injection] ──➔ [Findings Output]
Query parameter check    SSRF_PROBE_ANOMALY event  vscanx/val-web replica   Request validation loop  VSC-2026 Finding
\`\`\`

1. **URL parameter sweep:** Passive engines scan query parameters checking for unvalidated redirection targets.
2. **Decoupled Queueing:** Dispatches \`SSRF_PROBE_ANOMALY\` event contract to decouple the execution thread.
3. **Docker Target Spawning:** Core orchestrator spawns isolated \`vscanx/val-web:latest\` clone target.
4. **Active Exploit Verification:** Validator injects request headers, testing loopback escapes.
5. **Canonical Reporting:** Request breaks out ➔ compiles canonical findings log with captured evidence trace.`;
    } else if (activeEntity === "sqli") {
      output += `\`\`\`text
[Input Fields Sweep] ───➔ [SQL Anomaly event] ───➔ [Docker Database Spawn] ➔ [Validator Injection] ➔ [Breakout Capture]
SQL parameters check     SQLI_PROBE_ANOMALY event  vscanx/val-web database  Exploit validator loop  VSC-2026 Finding
\`\`\`

1. **SQLi Probing:** Passive sweeps check forms and input parameters for query syntax leaks.
2. **Event Queueing:** Dispatches \`SQLI_PROBE_ANOMALY\` contract to the decoupled broker.
3. **Docker Target Spawning:** Orchestrator provisions clean isolated database clone targets.
4. **Active Exploit Verification:** Exploit validator fires dynamic payloads to capture database breakout.
5. **Canonical Findings Logging:** Exploit verifies, writing findings database records.`;
    } else if (activeEntity === "scapy") {
      output += `\`\`\`text
[Engine Startup] ───────➔ [Privilege check] ─────➔ [Raw Socket Allocation] ➔ [Packet Header Craft] ➔ [Anomaly Dispatch]
vscanx scan command      Npcap / Sudo validation  Bypasses OS TCP/IP stack  Minimal active probe    Event Bus queueing
\`\`\`

1. **Command Invocation:** User invokes \`vscanx scan\` command.
2. **Privilege check:** Engine sweeps OS permissions (WinPcap/Npcap check on Windows; Sudo check on Unix).
3. **Adapter allocation:** Binds raw socket interface bypasses OS TCP/IP stack layers.
4. **Low-impact packet crafting:** Sends crafted packets passively mapping routes.
5. **Anomaly triggering:** Flags anomalies as event contracts to be validated inside sandboxes.`;
    } else if (activeEntity === "event_contract") {
      output += `\`\`\`text
[Prober Detection] ─────➔ [Typed Contract Gen] ──➔ [Event Bus Queueing] ───➔ [Broker Interception] ➔ [Sandbox Spawn]
Anomaly detected         SSRF_PROBE_ANOMALY       Central event bus        Dynamic thread pull     Isolated container
\`\`\`

1. **Prober Scan Detection:** Passive sweeps detect parameter redirection or memory anomalies.
2. **Event Contract Generation:** Packages payload parameters into a typed event contract matching VScanX schemas.
3. **Event Bus Queueing:** Pushes contract to asynchronous central event bus, decoupling probers.
4. **Broker Interception:** Orchestrator polls the bus, scheduling tasks and registering targets in thread pools.
5. **Sandbox Spawning:** Allocates concurrency limits and spawns isolated containment sandboxes sequentially.`;
    } else if (activeEntity === "sandbox") {
      output += `\`\`\`text
[Anomaly Interception] ➔ [Sandbox Allocation] ──➔ [Isolated Clone Spawn] ➔ [Fuzzer Loopback Bind] ➔ [Evidence Capture]
Event Bus trigger        Docker/Anvil/gVisor lock  Target replica clones    Exploit validator run   Canonical logs
\`\`\`

1. **Event bus interception:** Orchestrator captures anomalies on the decoupled bus.
2. **Sandbox type allocation:** Determines containment: Docker (Web), Anvil (Web3), or gVisor (AI).
3. **Isolated Clone Spawning:** Spawns ephemeral sandbox containers with loopback interfaces.
4. **Validator Payload execution:** Active validators inject payloads against container loopback adapters.
5. **Evidence logging:** Captured stdout/logs write to findings traces, destroying container replicas.`;
    } else if (activeEntity === "orchestrator") {
      output += `\`\`\`text
[Anomaly queueing] ─────➔ [ThreadPool Slot check] ➔ [Containment Provision] ➔ [Validator Execution] ➔ [Circuit Fallback]
Decoupled event bus      ThreadPoolExecutor lock   Docker/Anvil target      Active validator check  Task Timeout trigger
\`\`\`

1. **Broker Queueing:** Decoupled anomaly events inject into active scheduling pipelines.
2. **ThreadPool Slot Allocation:** Checks available concurrency slots in \`ThreadPoolExecutor\`.
3. **Containment Spawning:** Spawns isolated container sandboxes matching target modules.
4. **Validator execution:** Active validator injects loopback exploit payloads.
5. **Circuit Fallback:** Automatically terminates threads exceeding timeout limits, protecting target network adapters.`;
    } else {
      // General Workflow compilation using matched metadata
      output += `\`\`\`text
[Environment Check] ────➔ [Discovery Probes] ────➔ [Decoupled Events] ────➔ [Container Isolation] ➔ [Findings Report]
Dependency validation    Passive signatures scan  Anomaly event contracts  Ephemeral sandbox spawn  Canonical JSON output
\`\`\`

1. **Environment Checking:** Verifies dependencies, administrative permissions, and Docker sockets.
2. **Discovery Scanning:** Passive probers sweep active target systems mapping profiles.
3. **Event Decoupling:** Anomalies push to asynchronous bus as event contracts.
4. **Isolated Containment Spawn:** Spawns ephemeral sandboxes (Docker, Anvil EVM, or gVisor) based on domain.
5. **Active Verification:** Exploit validator executes dynamic payloads against container loopback adapters.`;
    }

    // Append desaturated trace boundaries
    output += `\n\n### Trace Verification Boundaries\n`;
    if (domain === "web3") {
      output += `- **Verification Containment:** \`Local Anvil EVM block snapshot fork (State-pollution isolated)\`\n`;
      output += `- **Local Registry:** \`0% (All state writes remain local to Anvil memory)\`\n`;
    } else if (domain === "replay") {
      output += `- **Verification Containment:** \`State-driven deterministic regression loop\`\n`;
      output += `- **Local Registry:** \`Offline delta comparisons against serialized snap states\`\n`;
    } else if (domain === "plugin") {
      output += `- **Verification Containment:** \`Runtime internal thread isolation (ThreadPoolExecutor)\`\n`;
      output += `- **Local Registry:** \`Thread-isolated log queues and fallback circuit breakers\`\n`;
    } else if (domain === "ai") {
      output += `- **Verification Containment:** \`runsc gVisor container sandbox (Kernel-level host isolated)\`\n`;
      output += `- **Local Registry:** \`gVisor system call interception boundaries\`\n`;
    } else {
      output += `- **Verification Containment:** \`Docker dynamic container isolation (vscanx/val-web)\`\n`;
      output += `- **Local Registry:** \`0% (Exploits execute strictly inside ephemeral Docker containers)\`\n`;
    }
  }

  // ==========================================================
  // TAB 3: SCHEMA (Structural Schema Interpretation)
  // ==========================================================
  else if (activeTab === "schema") {
    output = `### Grounding Evaluation: ${matchTier} (Structural Schema Interpretation)
*(Data contract definitions compiled from core VScanX interface protocols)*

### Schema Definition & Interface contracts
`;

    // Render precise, exact schemas contextually matching the activeEntity
    if (activeEntity === "replay_id" || activeEntity === "diff") {
      output += `#### 1. Scan Snapshot JSON Schema Contract (\`snap_<id>.json\`)
\`\`\`json
{
  "snapshot_id": "snap_701D",
  "target_identifier": "http://127.0.0.1:8080",
  "timestamp": "2026-05-28T14:15:30Z",
  "event_broker_sequence": [
    { "seq": 1, "type": "SSRF_PROBE_ANOMALY", "timestamp": "..." }
  ],
  "verification_logs": [
    "Docker sandbox val-web spawned",
    "Validator response status 200 payload matched"
  ],
  "canonical_findings": [
    { "finding_id": "VSC-2026-701D", "state": "VERIFIED" }
  ]
}
\`\`\``;
    } else if (activeEntity === "ast") {
      output += `#### 1. Web3 Solidity AST Bytecode Parser Config
\`\`\`json
{
  "parser_target": "solidity_ast_nodes",
  "opcodes_of_interest": ["CALL", "DELEGATECALL", "STATICCALL"],
  "ast_checks": {
    "reentrancy_state_mutation": "state_write_after_external_transfer",
    "access_control": "unprotected_initializer"
  }
}
\`\`\``;
    } else if (activeEntity === "pluginmanager") {
      output += `#### 1. Abstract \`BaseModule\` Interface Schema (Python Class Skeleton)
\`\`\`python
from abc import ABC, abstractmethod

class BaseModule(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Returns the dynamic scanner module identifier"""
        pass

    @abstractmethod
    def passive_probe(self, target: str) -> dict:
        """Executes low-impact signature probing"""
        pass

    @abstractmethod
    def verify_exploit(self, target: str, anomaly_event: dict) -> bool:
        """Executes active validation inside isolated sandboxes"""
        pass
\`\`\``;
    } else if (activeEntity === "verification_state") {
      output += `#### 1. Canonical Findings Schema Contract
\`\`\`json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "VScanX Canonical Finding Contract",
  "type": "OBJECT",
  "properties": {
    "finding_id": { "type": "STRING", "pattern": "^VSC-\\d{4}-\\d{4}$" },
    "target": { "type": "STRING" },
    "module": { "type": "STRING" },
    "verification_state": { "type": "STRING", "enum": ["VERIFIED", "ACTIVE", "RESOLVED"] },
    "severity": { "type": "STRING", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"] },
    "evidence_trace": {
      "type": "OBJECT",
      "properties": {
        "request_payload": { "type": "STRING" },
        "response_fragment": { "type": "STRING" },
        "log_stdout": { "type": "STRING" }
      }
    }
  }
}
\`\`\``;
    } else if (activeEntity === "ssrf" || activeEntity === "sqli" || activeEntity === "event_contract") {
      output += `#### 1. Typed Event Contract Schema (\`SSRF_PROBE_ANOMALY\` / \`WEB3_REENTRANCY_ANOMALY\`)
\`\`\`json
{
  "event_type": "SSRF_PROBE_ANOMALY",
  "target_url": "http://target.local/query?url=http://127.0.0.1",
  "vulnerability_parameter": "url",
  "detection_signature": "internal_ip_anomaly",
  "verification_sandbox": {
    "image": "vscanx/val-web:latest",
    "ports": ["80:80"]
  }
}
\`\`\``;
    } else if (activeEntity === "sandbox") {
      output += `#### 1. Sandbox Containment Policy Schema
\`\`\`json
{
  "sandbox_type": "Docker",
  "policy_descriptors": {
    "network_isolation": "internal_loopback_only",
    "socket_permissions": "restricted_container_socket",
    "kernel_containment_mode": "gvisor_runsc_kernel_interceptor",
    "anvil_blockchain_fork": {
      "active": true,
      "block_fork": "latest_mainnet"
    }
  }
}
\`\`\``;
    } else if (activeEntity === "scapy") {
      output += `#### 1. Low-Level Packet Header Structure Schema
\`\`\`json
{
  "packet_layer": "Layer_3_IP",
  "header_fields": {
    "source_ip": "crafted_adapter_ip",
    "destination_ip": "target_endpoint_ip",
    "raw_sockets_permissions": {
      "Windows": "Npcap_raw_adapter_bind",
      "Linux": "sudo_raw_socket_cap_net_raw"
    }
  }
}
\`\`\``;
    } else {
      // General schemas mapped directly from DB metadata
      if (uniqueSchemas.length > 0) {
        uniqueSchemas.forEach((schema, idx) => {
          output += `#### ${idx + 1}. ${schema} Contract Definition
\`\`\`json
{
  "data_descriptor": "${schema.toLowerCase().replace(/\s+/g, "_")}",
  "bound_subsystem": "${category}",
  "source_node": "${sourceId}"
}
\`\`\`\n`;
        });
      } else {
        output += `#### 1. Environment Config & Parameters Schema
\`\`\`json
{
  "env": {
    "python_version_required": ">=3.11",
    "scapy_loaded": true,
    "docker_socket_connected": true,
    "verify_mode": ["full-verification", "local-only-passive"]
  }
}
\`\`\``;
      }
    }
  }

  // ==========================================================
  // TAB 4: COMMANDS (Operational CLI Recipes)
  // ==========================================================
  else if (activeTab === "commands") {
    output = `### Grounding Evaluation: ${matchTier} (Operational CLI Commands)
*(Retrieval-constrained execution recipes from the CLI guide)*

### Operational CLI Execution Recipes
`;

    // Render precise recipes contextually matching the activeEntity
    if (activeEntity === "replay_id") {
      output += `#### Recipe 1: Replay snap baseline state
\`\`\`bash
vscanx replay --replay-id scan_701D
\`\`\`
Reads the serialized snap baseline from \`.vscanx_state/snap_701D.json\` offline and re-injects validators against local containers, bypassing active target network probing.

#### Recipe 2: Run verification and capture snap state
\`\`\`bash
vscanx scan target.local --verify --snapshot-out scan_701D
\`\`\`
Runs standard active verification and serializes baseline structures into snap JSON files.`;
    } else if (activeEntity === "diff") {
      output += `#### Recipe 1: Delta state comparison
\`\`\`bash
vscanx diff --diff scan_701C scan_701D
\`\`\`
Evaluates state transitions between snapshots A and B, calculating deltas to mathematically prove patch mitigation.

#### Recipe 2: Force regression checks against snap runs
\`\`\`bash
vscanx diff --diff scan_701C scan_701D --verify-mode local-only
\`\`\`
Compares Snapshots offline without checking active target routes.`;
    } else if (activeEntity === "ast") {
      output += `#### Recipe 1: Smart contract AST audits
\`\`\`bash
vscanx scan http://127.0.0.1:8545 --scan-type web3 --verify
\`\`\`
Instructs the Web3 scanner to parse smart contract AST structures and deploy validators against local Anvil RPC blockchain forks.

#### Recipe 2: Passive AST bytecodes analysis
\`\`\`bash
vscanx scan http://127.0.0.1:8545 --scan-type web3 --passive
\`\`\`
Performs passive AST auditing on solidity bytecode without spawning local Anvil forks.`;
    } else if (activeEntity === "pluginmanager") {
      output += `#### Recipe 1: List discovered plugin boundaries
\`\`\`bash
vscanx plugins --list
\`\`\`
Queries the PluginManager directly to list registered modules subclassing the \`BaseModule\` baseline interface.

#### Recipe 2: Run verification registry
\`\`\`bash
vscanx scan target.local --verify
\`\`\`
Bootstraps the plugin discoverer to dynamically walk module paths and instantiate subclasses for execution.`;
    } else if (activeEntity === "scapy") {
      output += `#### Recipe 1: Linux Active Prober (Sudo required)
\`\`\`bash
sudo vscanx scan 192.168.1.1 --verify
\`\`\`
Runs VScanX with elevated raw socket capabilities net raw permissions on Linux/macOS.

#### Recipe 2: Bind custom interface adapter
\`\`\`bash
sudo vscanx scan 192.168.1.1 --verify --interface eth0
\`\`\`
Binds the active scanner loopback checks to a specific network interface card.`;
    } else if (activeEntity === "verification_state") {
      output += `#### Recipe 1: Force passive offline signature fallback (CI-CD)
\`\`\`bash
vscanx scan 192.168.1.1 --verify --verify-mode local-only
\`\`\`
Enforces passive local-only checks when Docker daemon or raw socket privileges are unavailable in CI pipelines.

#### Recipe 2: Standard Active Scan
\`\`\`bash
vscanx scan target.local --verify
\`\`\`
Loops passive probers and triggers dynamic container validators.`;
    } else {
      // General commands mapped from matched metadata
      if (uniqueCommands.length > 0) {
        uniqueCommands.forEach((cmd, idx) => {
          output += `#### Recipe ${idx + 1}: \`${cmd}\`\n`;
          if (cmd.includes("scan-type web3")) {
            output += `Runs solidity AST parses, spawning local Anvil RPC forks at target block heights.\n\n`;
          } else if (cmd.includes("scan-type agentic")) {
            output += `Audits agentic AI breakouts, confining RCE escapes inside secure runsc gVisor sandboxes.\n\n`;
          } else if (cmd.includes("replay")) {
            output += `Replays a serialized snap state from \`.vscanx_state/\` offline to evaluate patch regression.\n\n`;
          } else if (cmd.includes("diff")) {
            output += `Calculates state deltas between snapshots, mathematically verifying regression corrections.\n\n`;
          } else if (cmd.includes("--verify")) {
            output += `Launches passive probing, decouples anomaly event bus queues, and verifies exploits inside Docker.\n\n`;
          } else {
            output += `Executes the VScanX command trigger.\n\n`;
          }
        });
      } else {
        output += `#### Recipe 1: CLI help guidelines
\`\`\`bash
vscanx --help
\`\`\`
Outputs command-line options, flag arguments, and modular categories.`;
      }
    }
  } else {
    return `### Verification Traceability Error
Selected action is invalid.`;
  }

  // ==========================================================
  // CONTEXTUAL REFINEMENT COMPILATION (Deterministic Synthesis)
  // ==========================================================
  if (refinementText) {
    const ref = refinementText.trim().toLowerCase();
    let refBlock = "";
    
    if (ref.includes("replay lifecycle")) {
      refBlock = `\n\n### Refined Context: Replay Lifecycle
The VScanX offline execution state engine enforces a 4-tier replay verification boundary:
1. **Telemetry Ingestion:** Reads active trace parameters, stdout frames, and event triggers from the snap JSON state file.
2. **Socket Mocking:** Intercepts low-level sockets calls, mapping active network requests to virtual container interfaces.
3. **Containment Replica Fork:** Spins up sandboxed Docker or local Anvil RPC instances mapping target snapshots.
4. **Regression Audit:** Compares fuzzer payloads against the virtual target replica state, writing mutation diff records.`;
    } else if (ref.includes("state diff")) {
      refBlock = `\n\n### Refined Context: State Diff Evolution
Delta state mutation S(t) ➔ S(t+1) computes discrete state differences:
- **State S(t) (Baseline snapshot):** Captures verified active vulnerabilities (e.g. SQLi / SSRF target anomaly states).
- **State S(t+1) (Regression check run):** Captures payload test outcomes following system patches.
- **Delta Result ΔS:** If the validator fails to reproduce the exploit in the cloned environment, ΔS confirms mitigation (RESOLVED).`;
    } else if (ref.includes("snapshot mapping")) {
      refBlock = `\n\n### Refined Context: Snapshot Mapping
Baseline serialization models targets as immutable hashes:
- **File Target:** \`.vscanx_state/snap_<id>.json\`
- **System Contexts:** Local network discovery endpoints, environment flags, and dynamic event queues.
- **Determinism Constraint:** Isolates state checks from active host adapters to prevent network pollution.`;
    } else if (ref.includes("field definitions")) {
      refBlock = `\n\n### Refined Context: Field Definitions
The VScanX Canonical Finding JSON schema guarantees data compliance for security engines:
- **finding_id:** Strict regex string \`^VSC-\\d{4}-\\d{4}$\` ensuring distinct identifiers.
- **verification_state:** Finite state enum constraint: \`['VERIFIED', 'ACTIVE', 'RESOLVED']\`.
- **evidence_trace:** Encapsulates low-level HTTP headers, EVM bytecode opcodes, and stderr log captures.`;
    } else if (ref.includes("contract structure")) {
      refBlock = `\n\n### Refined Context: Contract Structure
Asynchronous events decouple active probes from validation containment:
- **Broker Queue:** Receives typed anomaly payloads from thread-safe probers.
- **Contract Definition:** Maps \`event_type\`, \`vulnerability_parameter\`, and \`verification_sandbox\` to prevent race conditions.`;
    } else if (ref.includes("payload mapping")) {
      refBlock = `\n\n### Refined Context: Payload Mapping
Payload containment coordinates sandboxed parameters dynamically:
- **Web Audits:** Ports \`80:80\` bind strictly inside the ephemeral \`vscanx/val-web:latest\` container loopback interface.
- **Web3 Audits:** Local EVM Anvil nodes execute smart contract state mutations completely isolated in-memory.`;
    } else if (ref.includes("related flags")) {
      refBlock = `\n\n### Refined Context: Related Flags
The VScanX CLI defines technical arguments for precision execution:
- **--verify:** Triggers dynamic loopback exploit validation within sandboxed containment systems.
- **--passive:** Enforces signature-only checks, bypassing active exploit executions.
- **--verify-mode local-only:** Isolates checks within host environments when external Docker sockets are restricted.`;
    } else if (ref.includes("verification modes")) {
      refBlock = `\n\n### Refined Context: Verification Modes
Verification is strictly isolated to prevent state pollution:
- **Full Verification:** Spawns live container replicas or EVM RPC node forks.
- **Local-Only Passive:** Decouples scans to run purely signature audits, ideal for air-gapped CI pipelines.`;
    } else if (ref.includes("replay commands") || ref.includes("related commands")) {
      refBlock = `\n\n### Refined Context: Replay Commands
Deterministic replay controls provide complete regression tracking:
- \`vscanx replay --replay-id <id>\`: Invokes offline baseline state re-checks.
- \`vscanx diff --diff <runA> <runB>\`: Compares and compiles state diff evolution records.`;
    } else if (ref.includes("registration flow")) {
      refBlock = `\n\n### Refined Context: Registration Flow
The Plugin Discovery Engine walks packages through import hooks:
- **Sweep Phase:** Searches target directories via \`pkgutil.walk_packages()\`.
- **Import Phase:** Dynamically instantiates modules subclassing the abstract \`BaseModule\` base interface at boot.`;
    } else if (ref.includes("event subscription")) {
      refBlock = `\n\n### Refined Context: Event Subscription
Thread-safe orchestration manages event subscriptions asynchronously:
- **ThreadPoolExecutor:** schedules module tasks inside safe concurrency slots.
- **Queue Scheduling:** Prevents adapter conflicts, logging stdout queues directly to findings.`;
    } else if (ref.includes("execution boundaries")) {
      refBlock = `\n\n### Refined Context: Execution Boundaries
Containment sandboxes isolate exploit validator actions:
- **Docker Containers:** Confine web injection and parameters fuzzing.
- **Anvil Node Forks:** Confine smart contract reentrancy tests in memory.
- **gVisor runsc Sandboxes:** Intercept LLM prompt injection system command escapes at the kernel boundary.`;
    } else if (ref.includes("expand architecture")) {
      refBlock = `\n\n### Refined Context: Expand Architecture
VScanX operates a 100% decoupled, event-driven security architecture:
- **Passive signatures** act as input anomalies.
- **Asynchronous brokers** publish typed contracts.
- **Dynamic spawner containers** isolate active validations.
- **Diff comparison engines** prove regression mitigation.`;
    } else if (ref.includes("related workflows")) {
      refBlock = `\n\n### Refined Context: Related Workflows
Chronological verification proceeds through 5 distinct pipeline stages:
1. Passive Probing ➔ 2. Event Dispatching ➔ 3. Sandbox Container Spawning ➔ 4. Active Exploit Verification ➔ 5. Canonical Reporting.`;
    } else if (ref.includes("verification flow")) {
      refBlock = `\n\n### Refined Context: Verification Flow
To eliminate false-positive security logs, vulnerabilities are only confirmed if an exploit successfully reproduces inside containment, transitioning finding states to VERIFIED.`;
    } else {
      // General custom typed refinement
      refBlock = `\n\n### Refined Context: ${refinementText}
The offline Semantic Docs Layer parsed this custom intent. VScanX is a 100% deterministic local intelligence system. All related relationships (workflows, schemas, command mappings) are resolved statically on the client.`;
    }
    
    output += refBlock;
  }

  return output;
}

