# 🥷 Ninja (`remotego`)

**An ultra-high-throughput, zero-allocation, concurrent remote connection and probing engine for SSH and RDP in 100% Pure Go.**

[![Go Reference](https://pkg.go.dev/badge/github.com/mcoder/ninja.svg)](https://pkg.go.dev/github.com/mcoder/ninja)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Pure Go](https://img.shields.io/badge/CGO-Disabled%20(Pure%20Go)-success?style=flat)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Panic Guarantee](https://img.shields.io/badge/Reliability-Zero--Panic%20Engine-brightgreen)]()

---

## ⚡ Overview

**Ninja** (published under `remotego`) is an enterprise-grade Go SDK designed for massive, concurrent remote connection handling, reachability probing, banner fingerprinting, and credential validation against thousands of endpoints without risking runtime crashes, memory leaks, or operating system socket starvation.

While existing network probing libraries either depend on heavy C bindings (such as FreeRDP) or abandon RDP authentication entirely, Ninja provides a native, pure-Go implementation of **Microsoft CredSSP (MS-CSSP) and NTLMv2 (MS-NLMP)** alongside an optimized **SSH (RFC 4251)** engine.

---

## 🌟 Key Architecture Pillars

* **Pure Go (Zero CGO):** Compiles seamlessly across Linux, macOS, and Windows with static binary support and zero platform-specific toolchain requirements.
* **Full CredSSP & NTLMv2 Engine:** Native pure-Go implementation of CredSSP (v2–v6) with ASN.1 BER payload negotiation, NTLMv2 hash computation, client nonce crafting, and Windows NTSTATUS mapping.
* **Zero-Panic Guarantee:** Isolated recovery boundaries (`recover()`) wrap every spawned worker goroutine. Panic traces are recycled via `sync.Pool` to avoid memory fragmentation and mapped cleanly into structured domain errors.
* **Kernel Backpressure & Socket Protection:** Detects OS-level resource limits (`syscall.EMFILE`, `syscall.ENFILE`, `WSAENOBUFS`) and adaptively throttles concurrency to protect the local file-descriptor table.
* **Anti-Lockout Intelligent Retry Engine:** Exponential backoff with randomized jitter that distinguishes transient network timeouts from definitive auth failures (`INVALID_CREDENTIALS`, `ACCOUNT_LOCKED`), preventing Active Directory or PAM lockout triggers.
* **Granular Error Taxonomy:** Three-layer error classification (Network/L4, Protocol/L7, Auth) fully compatible with Go standard `errors.Is` and `errors.As`.

---

## 📊 Feature Comparison

| Feature | **Ninja (`remotego`)** | **ZGrab2** | **FreeRDP / CGO** | **Standard `net` Dialer** |
| :--- | :---: | :---: | :---: | :---: |
| **Pure Go (No CGO)** | ✅ **Yes** | ✅ Yes | ❌ No (Requires C) | ✅ Yes |
| **RDP NLA / CredSSP (NTLMv2)** | ✅ **Native** | ❌ No | ✅ Yes | ❌ No |
| **SSH Key & Keyboard-Interactive** | ✅ **Yes** | ⚠️ Partial | ❌ No | ❌ No |
| **Zero-Panic Isolation** | ✅ **Yes** | ❌ No | ❌ No | ❌ No |
| **Adaptive Socket Backpressure** | ✅ **Yes** | ❌ No | ❌ No | ❌ No |
| **Anti-Lockout Safety Engine** | ✅ **Yes** | ❌ No | ❌ No | ❌ No |
| **Banner Protocol Sniffing** | ✅ **Non-blocking** | ⚠️ Limited | ❌ No | ❌ No |

---

## 📥 Installation

```bash
go get github.com/mcoder/ninja@latest
```

---

## 🚀 Usage Examples

### 1. High-Concurrency Probing & Batch Dispatching

Probe thousands of endpoints concurrently with bounded or unbounded resource utilization:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mcoder/ninja/pkg/remotego"
)

func main() {
	client := remotego.NewClient(
		remotego.WithDialTimeout(4*time.Second),
		remotego.WithAuthTimeout(6*time.Second),
		remotego.WithRetries(2),
		remotego.WithMaxConcurrency(1000), // Set to 0 for unbounded concurrency
	)
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targets := []remotego.Target{
		{
			Host:     "192.168.1.10",
			Port:     22,
			Protocol: remotego.ProtocolSSH,
			Auth:     remotego.Password("admin", "P@ssword123"),
			Label:    "Linux-Node-01",
		},
		{
			Host:     "10.0.0.50",
			Port:     3389,
			Protocol: remotego.ProtocolRDP,
			Auth:     remotego.Password("CORP\\Administrator", "SecureP@ss2026"),
			Label:    "Windows-DC",
		},
		{
			Host:     "192.168.1.200",
			Port:     22,
			Protocol: remotego.ProtocolSSH,
			Auth:     remotego.NoAuth(),
			Label:    "SSH-Asset-Discovery",
		},
	}

	resultsChan := client.DispatchBatch(ctx, targets)

	for res := range resultsChan {
		fmt.Printf("[%s] Target: %s\n", res.Target.Label, res.Target.Addr())
		fmt.Printf(" -> Reachable: %v | Handshake OK: %v | Auth OK: %v | Banner: %s\n",
			res.Probe.Reachable, res.Probe.ProtocolConfirmed, res.Probe.AuthOK, res.Probe.Banner)

		if res.Probe.Err != nil {
			var rErr *remotego.RemoteError
			if errors.As(res.Probe.Err, &rErr) {
				switch rErr.Code {
				case remotego.ErrCodeInvalidCredentials:
					fmt.Printf(" [!] Authentication failed: Invalid username or password\n")
				case remotego.ErrCodeAccountLocked:
					fmt.Printf(" [!] Target reported account lockout / disabled\n")
				case remotego.ErrCodeProtocolMismatch:
					fmt.Printf(" [!] Protocol Mismatch: %s\n", rErr.Detail)
				case remotego.ErrCodeSocketExhaustion:
					fmt.Printf(" [!] System socket pressure detected (Auto-throttling active)\n")
				default:
					fmt.Printf(" [x] Failure: %v (Phase: %s)\n", rErr, rErr.Phase)
				}
			}
		}
	}
}
```

---

### 2. Establishing Stateful Sessions (SSH Command Execution)

Establish an authenticated stateful session to execute commands:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/mcoder/ninja/pkg/remotego"
)

func main() {
	client := remotego.NewClient()
	defer client.Close()

	session, err := client.Dial(context.Background(), remotego.Target{
		Host:     "192.168.1.100",
		Port:     22,
		Protocol: remotego.ProtocolSSH,
		Auth:     remotego.Password("ubuntu", "secret"),
	})
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}
	defer session.Close()

	if exec, ok := session.(remotego.CommandExecutor); ok {
		output, err := exec.Exec(context.Background(), "uptime && uname -a")
		if err != nil {
			log.Fatalf("Command error: %v", err)
		}
		fmt.Printf("Remote Output:\n%s", string(output))
	}
}
```

---

## 🧭 Error Taxonomy

Every error emitted across API boundaries is classified under a unified `ErrorCode`:

| Phase | ErrorCode | Description | Default Retry Policy |
| :--- | :--- | :--- | :---: |
| **Network (L4)** | `TIMEOUT` | Socket dial or I/O deadline exceeded | ✅ Retryable |
| | `CONNECTION_REFUSED` | TCP SYN reset by target | ✅ Retryable |
| | `HOST_UNREACHABLE` | ICMP host unreachable or no route | ✅ Retryable |
| | `SOCKET_EXHAUSTION` | Host OS exhausted file descriptors (`EMFILE`, `ENOBUFS`) | ✅ Retryable (Throttles) |
| **Protocol (L7)** | `PROTOCOL_MISMATCH` | Port speaks unexpected protocol (e.g., HTTP on 22) | ❌ Non-retryable |
| | `HANDSHAKE_CORRUPTED` | Malformed TPKT/X.224 frame or key exchange error | ✅ Retryable |
| | `TLS_FAILURE` | TLS negotiation error or handshake reset | ✅ Retryable |
| **Auth** | `INVALID_CREDENTIALS` | Bad credentials (NTSTATUS `0xC000006A` / SSH Auth Fail) | ❌ **Non-retryable (Safety)** |
| | `ACCOUNT_LOCKED` | Account locked or disabled (NTSTATUS `0xC0000234`) | ❌ **Non-retryable (Safety)** |
| | `KEY_REJECTED` | SSH public key was not accepted | ❌ **Non-retryable (Safety)** |
| | `MFA_CHALLENGE_REQUIRED` | Target requires interactive MFA challenge | ❌ Non-retryable |

---

## 🛠️ Configuration Options

| Option | Default | Purpose |
| :--- | :---: | :--- |
| `WithMaxConcurrency(n)` | `0` (Unbounded) | Max concurrent workers. Set to `0` for unbounded scheduler scaling. |
| `WithDialTimeout(d)` | `10s` | Maximum time to complete initial L4 TCP connection. |
| `WithHandshakeTimeout(d)`| `10s` | Maximum time for protocol negotiation and TLS handshake. |
| `WithAuthTimeout(d)` | `15s` | Maximum time for CredSSP or SSH authentication. |
| `WithRetries(n)` | `0` (Disabled) | Number of retry attempts on transient network failures. |
| `WithRateLimit(r, burst)` | Disabled | Token-bucket rate limiter specifying operations started per second. |
| `WithAdaptiveRateLimit(b)`| Disabled | Automatically halves request rate upon observing local socket exhaustion. |
| `WithNoDelay(b)` | `true` | Enables or disables `TCP_NODELAY` (Nagle's algorithm). |

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
