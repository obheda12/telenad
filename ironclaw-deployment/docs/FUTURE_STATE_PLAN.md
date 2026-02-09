# Future State Plan: Path to Maximum Security

This document outlines the evolutionary path from the current "Option A" deployment to increasingly secure configurations, ultimately achieving near-zero residual risk for all identified threat vectors.

---

## Current State Assessment

### Risk Matrix (Option A - Current)

| Threat | Current Risk | Target Risk | Gap |
|--------|--------------|-------------|-----|
| Credential theft | Very Low | Impossible | Small |
| Unauthorized message sending | Low | Impossible | Medium |
| Data exfiltration to external hosts | Very Low | Impossible | Small |
| Prompt injection → bad reasoning | **Medium** | Low | **Large** |
| Information disclosure via manipulation | **Medium** | Low | **Large** |
| WASM sandbox escape | Very Low | Very Low | None |
| Supply chain compromise | Low | Very Low | Small |
| Configuration drift/error | Low | Very Low | Small |

### Why Current Risks Exist

**1. Config-Level vs Architectural Blocking**
```
Current: sendMessage blocked by settings.toml
         ↓
Problem: Config can be misconfigured, IronClaw bug could bypass

Target:  sendMessage not in WASM tool's compiled capabilities
         ↓
Result:  Architecturally impossible, not just blocked
```

**2. Shared Process Space**
```
Current: Credentials and LLM reasoning in same IronClaw process
         ↓
Problem: Memory corruption or IronClaw vulnerability could leak

Target:  Credentials in separate process with no LLM
         ↓
Result:  Even full IronClaw compromise can't access credentials
```

**3. LLM Susceptibility**
```
Current: LLM sees raw message content, can be manipulated
         ↓
Problem: Prompt injection affects reasoning quality

Target:  Multiple LLM calls with cross-validation
         ↓
Result:  Single injection can't compromise all reasoning paths
```

---

## Evolution Phases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SECURITY EVOLUTION PATH                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 0 (Current)          PHASE 1                PHASE 2                  │
│  ─────────────────          ───────                ───────                  │
│  Option A:                  Option B:              Option B+:               │
│  Config-based blocking      Custom WASM Tool       + Network Firewall       │
│                                                                             │
│  ┌─────────────────┐       ┌─────────────────┐    ┌─────────────────┐      │
│  │ IronClaw        │       │ IronClaw        │    │ IronClaw        │      │
│  │ ┌─────────────┐ │       │ ┌─────────────┐ │    │ ┌─────────────┐ │      │
│  │ │ Telegram    │ │       │ │ TG ReadOnly │ │    │ │ TG ReadOnly │ │      │
│  │ │ Tool        │ │  ───► │ │ Tool        │ │───►│ │ Tool        │ │      │
│  │ │ (blocked by │ │       │ │ (no send    │ │    │ │ (no send    │ │      │
│  │ │  config)    │ │       │ │  capability)│ │    │ │  capability)│ │      │
│  │ └─────────────┘ │       │ └─────────────┘ │    │ └─────────────┘ │      │
│  └─────────────────┘       └─────────────────┘    └────────┬────────┘      │
│                                                             │               │
│  Risk: Config error         Risk: IronClaw bug    iptables/nftables        │
│        could enable send          could bypass     blocks non-TG traffic   │
│                                                             │               │
│                                                    ┌────────▼────────┐      │
│                                                    │ Kernel-level    │      │
│                                                    │ network filter  │      │
│                                                    └─────────────────┘      │
│                                                                             │
│                                                                             │
│  PHASE 3                    PHASE 4                PHASE 5 (Ultimate)       │
│  ───────                    ───────                ──────────────────       │
│  Option C:                  Option C+:             Hardware Security        │
│  Air-Gapped Architecture    + HSM/TPM              Module + Formal          │
│                                                    Verification             │
│                                                                             │
│  ┌─────────────────┐       ┌─────────────────┐    ┌─────────────────┐      │
│  │ Ingest Service  │       │ Ingest Service  │    │ Ingest Service  │      │
│  │ (has creds,     │       │ (has creds in   │    │ (creds in HSM,  │      │
│  │  no LLM)        │       │  TPM/HSM)       │    │  no LLM)        │      │
│  └────────┬────────┘       └────────┬────────┘    └────────┬────────┘      │
│           │ write                   │                      │               │
│           ▼                         ▼                      ▼               │
│  ┌─────────────────┐       ┌─────────────────┐    ┌─────────────────┐      │
│  │   PostgreSQL    │       │   PostgreSQL    │    │   PostgreSQL    │      │
│  │ (sanitized msgs)│       │ (sanitized msgs)│    │ (sanitized,     │      │
│  └────────┬────────┘       └────────┬────────┘    │  schema-locked) │      │
│           │ read-only               │             └────────┬────────┘      │
│           ▼                         ▼                      │               │
│  ┌─────────────────┐       ┌─────────────────┐            ▼               │
│  │ IronClaw Agent  │       │ IronClaw Agent  │    ┌─────────────────┐      │
│  │ (no creds,      │       │ (no creds,      │    │ IronClaw Agent  │      │
│  │  no network)    │       │  no network,    │    │ (formally       │      │
│  └─────────────────┘       │  verified WASM) │    │  verified, no   │      │
│                            └─────────────────┘    │  creds/network) │      │
│  Risk: DB compromise       Risk: HSM bypass      └─────────────────┘      │
│        exposes messages           (very hard)                              │
│                                                   Risk: Hardware fault     │
│                                                         (very rare)        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Custom Read-Only WASM Tool

**Objective**: Move from config-level blocking to architectural impossibility of sending messages.

**Timeline**: 1-2 days

**Risk Reduction**: Message sending moves from "Low" to "Very Low"

### Implementation

Create a custom WASM tool that only declares read capabilities:

```rust
// telegram_readonly/src/lib.rs
use ironclaw_sdk::prelude::*;

/// Telegram Read-Only Tool
/// This tool CANNOT send messages - the capability is not declared.
/// Even if the LLM requests sendMessage, the WASM runtime will reject it.

#[tool(name = "telegram_readonly")]
pub struct TelegramReadOnly;

#[tool_impl]
impl TelegramReadOnly {
    /// Fetch recent messages from Telegram
    #[tool_method]
    pub async fn get_updates(
        &self,
        ctx: &ToolContext,
        #[arg(desc = "Maximum number of messages to fetch")]
        limit: Option<u32>,
        #[arg(desc = "Offset for pagination")]
        offset: Option<i64>,
    ) -> Result<Vec<TelegramMessage>, ToolError> {
        let limit = limit.unwrap_or(100).min(100);

        let response = ctx.http()
            .get("https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates")
            .query(&[("limit", limit.to_string())])
            .query(&[("offset", offset.map(|o| o.to_string()).unwrap_or_default())])
            .send()
            .await?;

        // Parse and return messages
        let updates: TelegramUpdates = response.json().await?;
        Ok(updates.result.into_iter().map(|u| u.message).collect())
    }

    /// Get information about the bot
    #[tool_method]
    pub async fn get_me(&self, ctx: &ToolContext) -> Result<BotInfo, ToolError> {
        let response = ctx.http()
            .get("https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getMe")
            .send()
            .await?;

        Ok(response.json().await?)
    }

    /// Get information about a chat
    #[tool_method]
    pub async fn get_chat(
        &self,
        ctx: &ToolContext,
        #[arg(desc = "Chat ID to get information about")]
        chat_id: i64,
    ) -> Result<ChatInfo, ToolError> {
        let response = ctx.http()
            .get("https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getChat")
            .query(&[("chat_id", chat_id.to_string())])
            .send()
            .await?;

        Ok(response.json().await?)
    }
}

// CRITICAL: Capability declarations
// This is what makes sending ARCHITECTURALLY IMPOSSIBLE
#[capabilities]
impl TelegramReadOnly {
    fn capabilities() -> Vec<Capability> {
        vec![
            // HTTP access ONLY to these specific endpoints
            Capability::Http {
                url_pattern: "https://api.telegram.org/bot*/getUpdates*",
                methods: vec![HttpMethod::Get],
            },
            Capability::Http {
                url_pattern: "https://api.telegram.org/bot*/getMe",
                methods: vec![HttpMethod::Get],
            },
            Capability::Http {
                url_pattern: "https://api.telegram.org/bot*/getChat*",
                methods: vec![HttpMethod::Get],
            },
            // Secret injection
            Capability::Secret("TELEGRAM_BOT_TOKEN"),

            // NOTE: No sendMessage, no POST methods, no other endpoints
            // The WASM runtime will REJECT any attempt to call them
        ]
    }
}
```

### Build and Deploy

```bash
# Build WASM tool
cd telegram_readonly
cargo build --target wasm32-wasi --release

# Install to IronClaw
mkdir -p ~/.ironclaw/tools
cp target/wasm32-wasi/release/telegram_readonly.wasm ~/.ironclaw/tools/

# Update settings.toml
[tools]
telegram = { enabled = false }  # Disable stock tool
telegram_readonly = { enabled = true, path = "~/.ironclaw/tools/telegram_readonly.wasm" }
```

### Verification

```bash
# Attempt to send message via IronClaw
> Send a message to chat 12345 saying "test"

# Expected response:
# "I don't have the capability to send messages. My telegram_readonly tool
#  only supports: get_updates, get_me, get_chat"

# Check WASM capabilities
ironclaw tools inspect telegram_readonly
# Should show ONLY get* methods, no send*
```

---

## Phase 2: Network-Level Firewall

**Objective**: Add kernel-level network restrictions as defense-in-depth against IronClaw bugs.

**Timeline**: 2-4 hours

**Risk Reduction**: Exfiltration moves from "Very Low" to "Near Impossible"

### Implementation

```bash
# /etc/nftables.conf (or iptables equivalent)

#!/usr/sbin/nft -f

flush ruleset

table inet ironclaw_isolation {
    chain output {
        type filter hook output priority 0; policy accept;

        # Allow loopback
        oif "lo" accept

        # Allow established connections
        ct state established,related accept

        # Allow DNS (needed for api.telegram.org resolution)
        udp dport 53 accept
        tcp dport 53 accept

        # Allow ONLY Telegram API
        # Telegram API IPs (update periodically)
        ip daddr 149.154.160.0/20 tcp dport 443 accept
        ip daddr 91.108.4.0/22 tcp dport 443 accept
        ip daddr 91.108.8.0/22 tcp dport 443 accept
        ip daddr 91.108.12.0/22 tcp dport 443 accept
        ip daddr 91.108.16.0/22 tcp dport 443 accept
        ip daddr 91.108.56.0/22 tcp dport 443 accept

        # Block everything else for ironclaw user
        meta skuid "ironclaw" drop
    }
}
```

### Alternative: Per-Process Network Namespace

```bash
# Create isolated network namespace for IronClaw
ip netns add ironclaw_ns

# Create veth pair
ip link add veth-ic type veth peer name veth-ic-ns
ip link set veth-ic-ns netns ironclaw_ns

# Configure routing (only to Telegram)
ip netns exec ironclaw_ns ip route add 149.154.160.0/20 via <gateway>
# ... repeat for other Telegram ranges

# Run IronClaw in namespace
ip netns exec ironclaw_ns sudo -u ironclaw /home/pi/ironclaw/target/release/ironclaw
```

---

## Phase 3: Air-Gapped Architecture (Option C)

**Objective**: Complete separation of credentials from LLM reasoning.

**Timeline**: 1-2 weeks

**Risk Reduction**: Credential theft becomes "Impossible" (not just "Very Low")

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        AIR-GAPPED ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  CREDENTIAL ZONE                    │           LLM ZONE                    │
│  (Has secrets, no AI)               │           (Has AI, no secrets)        │
│                                     │                                       │
│  ┌─────────────────────┐            │                                       │
│  │   INGEST SERVICE    │            │                                       │
│  │                     │            │                                       │
│  │ • Rust daemon       │            │                                       │
│  │ • Telegram creds    │            │                                       │
│  │ • NO LLM            │            │                                       │
│  │ • NO prompt input   │            │                                       │
│  │                     │            │                                       │
│  │ Function:           │            │                                       │
│  │ 1. Poll Telegram    │            │                                       │
│  │ 2. Sanitize msgs    │            │            ┌─────────────────────┐    │
│  │ 3. Write to DB      │───────────────────────► │   POSTGRESQL        │    │
│  │                     │   (one-way write)       │                     │    │
│  └─────────────────────┘            │            │ • Sanitized msgs    │    │
│           │                         │            │ • Embeddings        │    │
│           │                         │            │ • Audit logs        │    │
│           │ Telegram                │            └──────────┬──────────┘    │
│           │ API                     │                       │               │
│           ▼                         │                       │ read-only     │
│  ┌─────────────────────┐            │                       ▼               │
│  │   TELEGRAM API      │            │            ┌─────────────────────┐    │
│  │   (external)        │            │            │   IRONCLAW AGENT    │    │
│  └─────────────────────┘            │            │                     │    │
│                                     │            │ • LLM reasoning     │    │
│                                     │            │ • NO credentials    │    │
│                                     │            │ • NO network        │    │
│                                     │            │ • DB read-only      │    │
│                                     │            │                     │    │
│                                     │            │ Even if fully       │    │
│                                     │            │ compromised:        │    │
│                                     │            │ • Can't send msgs   │    │
│                                     │            │ • Can't exfiltrate  │    │
│                                     │            │ • Can't get creds   │    │
│                                     │            └─────────────────────┘    │
│                                     │                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Ingest Service Implementation

```rust
// ingest-service/src/main.rs

use teloxide::prelude::*;
use sqlx::PgPool;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load credentials from secure storage
    let token = std::env::var("TELEGRAM_BOT_TOKEN")?;
    let db_url = std::env::var("DATABASE_URL")?;

    let bot = Bot::new(token);
    let pool = PgPool::connect(&db_url).await?;

    // Main polling loop
    loop {
        match fetch_and_store(&bot, &pool).await {
            Ok(count) => tracing::info!("Processed {} messages", count),
            Err(e) => tracing::error!("Error: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn fetch_and_store(bot: &Bot, pool: &PgPool) -> Result<usize, Error> {
    let updates = bot.get_updates().await?;
    let mut count = 0;

    for update in updates {
        if let Some(msg) = update.message {
            // Sanitize before storage
            let sanitized = sanitize_message(&msg);

            // Store sanitized version only
            sqlx::query!(
                r#"
                INSERT INTO messages (telegram_id, chat_id, sender_name, content_sanitized, received_at)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (telegram_id) DO NOTHING
                "#,
                msg.id,
                msg.chat.id,
                msg.from.map(|u| u.first_name),
                sanitized.content,
                msg.date,
            )
            .execute(pool)
            .await?;

            count += 1;
        }
    }

    Ok(count)
}

fn sanitize_message(msg: &Message) -> SanitizedMessage {
    let mut content = msg.text().unwrap_or_default().to_string();

    // 1. Detect and flag injection attempts
    let injection_patterns = [
        "ignore previous",
        "ignore all instructions",
        "system prompt",
        "you are now",
        "new instructions",
        "override",
        "admin mode",
    ];

    let mut flags = Vec::new();
    for pattern in &injection_patterns {
        if content.to_lowercase().contains(pattern) {
            flags.push(format!("INJECTION_PATTERN:{}", pattern));
        }
    }

    // 2. Encode/neutralize URLs
    content = URL_REGEX.replace_all(&content, "[URL REMOVED]").to_string();

    // 3. Truncate to prevent context stuffing
    if content.len() > 4000 {
        content = format!("{}... [TRUNCATED]", &content[..4000]);
    }

    // 4. Escape any remaining control sequences
    content = content.replace('\x00', "");

    SanitizedMessage {
        content,
        flags,
        original_length: msg.text().map(|t| t.len()).unwrap_or(0),
    }
}
```

### Database Schema for Air-Gapped Mode

```sql
-- Strict schema to prevent injection via DB

CREATE TABLE messages (
    id              BIGSERIAL PRIMARY KEY,
    telegram_id     BIGINT UNIQUE NOT NULL,
    chat_id         BIGINT NOT NULL,
    sender_name     VARCHAR(255),  -- Limited length
    content_sanitized TEXT NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ DEFAULT NOW(),
    flags           TEXT[],        -- Injection detection flags

    -- Constraints prevent injection via field values
    CONSTRAINT valid_chat_id CHECK (chat_id > 0),
    CONSTRAINT content_not_empty CHECK (length(content_sanitized) > 0),
    CONSTRAINT content_max_length CHECK (length(content_sanitized) <= 10000)
);

-- IronClaw connects with read-only role
CREATE ROLE ironclaw_readonly;
GRANT CONNECT ON DATABASE ironclaw TO ironclaw_readonly;
GRANT SELECT ON messages TO ironclaw_readonly;
-- NO INSERT, UPDATE, DELETE granted

-- Ingest service has write access
CREATE ROLE ingest_service;
GRANT CONNECT ON DATABASE ironclaw TO ingest_service;
GRANT INSERT ON messages TO ingest_service;
-- NO SELECT needed (write-only)
```

---

## Phase 4: Hardware Security Module (HSM/TPM)

**Objective**: Store credentials in tamper-resistant hardware.

**Timeline**: 1 week + hardware procurement

**Risk Reduction**: Credential theft requires physical hardware attack

### Raspberry Pi TPM Option

```bash
# Install TPM2 tools
sudo apt install tpm2-tools tpm2-abrmd

# Store Telegram token in TPM
echo -n "$TELEGRAM_BOT_TOKEN" | tpm2_nvdefine -C o -s 64 -a "ownerread|ownerwrite" 0x1500001
echo -n "$TELEGRAM_BOT_TOKEN" | tpm2_nvwrite -C o -i - 0x1500001

# Ingest service reads from TPM at runtime
# Token never touches filesystem
```

### External HSM Option (Higher Security)

For maximum security, use a dedicated HSM like:
- YubiHSM 2 (~$650)
- Nitrokey HSM 2 (~$109)
- AWS CloudHSM (cloud, but hardware-backed)

```rust
// Reading from YubiHSM
use yubihsm::{Client, Credentials, HttpConfig};

async fn get_telegram_token(hsm: &Client) -> Result<String, Error> {
    // Token stored as opaque object in HSM
    // Even if system is compromised, token can only be USED, not EXTRACTED
    let token_bytes = hsm.get_opaque(TELEGRAM_TOKEN_ID)?;
    Ok(String::from_utf8(token_bytes)?)
}
```

---

## Phase 5: Formal Verification (Ultimate)

**Objective**: Mathematical proof that the system cannot perform unauthorized actions.

**Timeline**: 3-6 months (research project)

**Risk Reduction**: Unauthorized actions become "Provably Impossible"

### Approach

1. **Define Security Properties**
   ```
   Property 1: ∀ execution paths, no HTTP POST to telegram.org
   Property 2: ∀ execution paths, TELEGRAM_BOT_TOKEN not in output
   Property 3: ∀ execution paths, only allowlisted URLs accessed
   ```

2. **Verify WASM Tool**
   - Use tools like Kani (Rust model checker) or WASM symbolic execution
   - Prove the compiled WASM cannot violate properties

3. **Verify Host Boundary**
   - Prove IronClaw's allowlist implementation is correct
   - Prove credential injection happens only after allowlist check

4. **Verify Network Stack**
   - Prove iptables/nftables rules enforce expected behavior
   - Use network verification tools (Batfish, etc.)

### Example Kani Verification

```rust
#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_no_send_capability() {
        let tool = TelegramReadOnly;
        let caps = tool.capabilities();

        // Prove: no capability allows sendMessage
        for cap in caps {
            if let Capability::Http { url_pattern, methods } = cap {
                kani::assert!(
                    !url_pattern.contains("sendMessage"),
                    "Tool must not have sendMessage capability"
                );
                kani::assert!(
                    !methods.contains(&HttpMethod::Post),
                    "Tool must not have POST capability to Telegram"
                );
            }
        }
    }

    #[kani::proof]
    fn verify_credential_not_leaked() {
        let ctx = kani::any::<ToolContext>();
        let result = TelegramReadOnly.get_updates(&ctx, Some(10), None);

        // Prove: output never contains token pattern
        if let Ok(messages) = result {
            for msg in messages {
                kani::assert!(
                    !msg.content.contains("bot") || !msg.content.contains(":"),
                    "Output must not contain token-like patterns"
                );
            }
        }
    }
}
```

---

## Summary: Risk Reduction by Phase

| Threat | Phase 0 | Phase 1 | Phase 2 | Phase 3 | Phase 4 | Phase 5 |
|--------|---------|---------|---------|---------|---------|---------|
| Credential theft | Very Low | Very Low | Very Low | **Impossible** | **Impossible** | **Proven** |
| Send message | Low | **Very Low** | **Very Low** | **Impossible** | **Impossible** | **Proven** |
| Exfiltration | Very Low | Very Low | **Near Impossible** | **Impossible** | **Impossible** | **Proven** |
| Bad reasoning | Medium | Medium | Medium | Medium | Medium | Low |
| Info disclosure | Medium | Medium | Medium | Low | Low | Low |
| WASM escape | Very Low | Very Low | Very Low | Very Low | Very Low | **Proven** |
| Supply chain | Low | Low | Low | Very Low | Very Low | Low |
| Config error | Low | **Very Low** | **Very Low** | **Very Low** | **Very Low** | N/A |

### Recommended Implementation Order

1. **Phase 1** (Custom WASM) - Do immediately, high ROI
2. **Phase 2** (Firewall) - Do immediately, low effort
3. **Phase 3** (Air-gap) - Do if handling sensitive data
4. **Phase 4** (HSM) - Do if compliance requires or high-value target
5. **Phase 5** (Formal) - Research project, aspirational

---

## Appendix: Residual Risks That Cannot Be Fully Mitigated

Some risks are inherent to the use case and cannot be eliminated:

### 1. LLM Reasoning Manipulation
**Why it persists**: The LLM must process message content to be useful. Adversarial content can influence reasoning.

**Mitigation strategies** (reduce, not eliminate):
- Multi-model verification (use different LLMs, compare outputs)
- Confidence scoring (flag low-confidence responses)
- Human review for sensitive queries

### 2. Information Already in Context
**Why it persists**: If the agent has read sensitive messages, it "knows" them. Prompt injection might extract this.

**Mitigation strategies**:
- Minimize context window (don't load all messages)
- Separate sensitive chats (different databases)
- Time-based expiry (forget old messages)

### 3. Physical Device Compromise
**Why it persists**: Someone with physical access can extract data.

**Mitigation strategies**:
- Full disk encryption (LUKS)
- TPM-sealed encryption keys
- Physical security (locked room)
- Tamper-evident enclosures

### 4. Upstream Dependency Vulnerabilities
**Why it persists**: We depend on Rust, wasmtime, IronClaw, PostgreSQL, Linux kernel.

**Mitigation strategies**:
- Keep dependencies updated
- Monitor CVE databases
- Use minimal dependency set
- Consider reproducible builds
