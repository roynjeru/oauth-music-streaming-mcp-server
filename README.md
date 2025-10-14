
# 🎧 Spotify OAuth 2.0 Authorization Server (with MCP Authentication)

[![.NET](https://img.shields.io/badge/.NET-8.0-blue.svg)](https://dotnet.microsoft.com/)
[![OAuth 2.0](https://img.shields.io/badge/OAuth-2.0-green.svg)](https://oauth.net/2/)
[![OpenID Connect](https://img.shields.io/badge/OpenID-Connect-orange.svg)](https://openid.net/connect/)
[![MCP](https://img.shields.io/badge/MCP-Auth%20Server-purple.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

> Secure OAuth 2.0 and MCP-compliant authorization server bridging **Spotify’s Web API** with **Model Context Protocol (MCP)** tool servers — built for scale, observability, and developer experience.

---

## 📖 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
  - [Authorization Code with PKCE](#1-oauth-20-authorization-code-with-pkce-spotify-integration)
  - [Dynamic Client Registration](#2-dynamic-client-registration-rfc-7591-33)
  - [RSA-Signed Bearer Tokens](#3-rsa-signed-bearer-tokens-jwt)
  - [Addressing MCP Authentication Challenges](#4-addressing-mcp-authentication-challenges)
  - [Token Lifecycle and Security](#5-token-lifecycle-and-security)
- [Architecture](#-architecture)
- [Security Highlights](#️-security-highlights)
- [Future Enhancements](#-future-enhancements)
- [Running Locally](#-running-locally)
- [License](#-license)

---

## 🧭 Overview

This repository implements a **custom OAuth 2.0 Authorization Server** that bridges authentication between:
- **Spotify Web API** (user identity & consent)  
- **Model Context Protocol (MCP) servers** exposing Spotify tool integrations  

Built with **ASP.NET Core 8**, it delivers a secure and extensible authentication layer using:
- **PKCE-based Authorization Code Flow**
- **Dynamic Client Registration**
- **RSA-signed JWT bearer tokens**
- **OpenID Connect Discovery**
- **MCP Authorization Compliance** per [specification 2025-03-26](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)

---

## 🚀 Key Features

### 1. OAuth 2.0 Authorization Code with PKCE (Spotify Integration)

Implements Spotify’s [Authorization Code with PKCE flow](https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow) for secure public-client authentication.

**Flow Summary:**
1. Client starts `/authorize` with `code_challenge=S256`
2. Server redirects to Spotify for user consent  
3. Spotify returns an auth `code` → `/spotify-callback`  
4. Server exchanges Spotify code for access/refresh tokens  
5. MCP issues its own JWT-bound token (`/token`)


[Sequence Diagram](./diagrams/sequence%20diagram.png)


This ensures that no secrets are exposed client-side and that token exchanges are verified using `code_verifier` and `S256`.

```csharp
var spotifyTokenRequest = new SpotifyTokenRequest
{
    GrantType = "authorization_code",
    Code = code,
    RedirectUri = redirectUri,
    CodeVerifier = verifier
};
````

---

### 2. Dynamic Client Registration (RFC 7591 §3.3)

Enables runtime client onboarding without manual setup.

**Example Request:**

```http
POST /register
Content-Type: application/json

{
  "client_name": "my-mcp-client",
  "redirect_uris": ["https://localhost:3000/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "mcp:tools openid profile email"
}
```

**Response:**

```json
{
  "client_id": "abc123",
  "registration_access_token": "securetoken",
  "registration_client_uri": "https://localhost:8080/register/abc123"
}
```

#### 💡 Why it matters

Dynamic registration allows **multi-tenant tool ecosystems** to register securely at runtime — ideal for **automated AI agent provisioning** and **decentralized MCP tool discovery**.

📘 Reference: [RFC 7591 §3.3](https://datatracker.ietf.org/doc/html/rfc7591#section-3.3)

---

### 3. RSA-Signed Bearer Tokens (JWT)

Access tokens are minted as **RSA-signed JWTs** using a PEM private key, encapsulated by the [`RsaJwtIssuer`](./RsaJwtIssuer.cs) class.

```csharp
var jwt = issuerSvc.Mint("user1", lifetime: TimeSpan.FromMinutes(15));
```

* `iss`: MCP issuer URL
* `aud`: `"my-mcp-server"`
* `sub`: Spotify-linked user identity
* `kid`: RSA key identifier
* `exp`: short-lived (15 minutes)

JWTs are signed with **RS256**, verified via the published **JWKS** endpoint (`/.well-known/jwks.json`).

📘 Reference: [MCP Authorization Spec (Mar 2025)](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)

---

### 4. Addressing MCP Authentication Challenges

According to [GoFastMCP Authentication](https://gofastmcp.com/servers/auth/authentication), secure MCP auth requires handling federated identity, token delegation, and proof-of-possession.

| **Challenge**                               | **Solution Implemented**                                                         |
| ------------------------------------------- | -------------------------------------------------------------------------------- |
| Decoupled identity sources (Spotify vs MCP) | Spotify tokens are federated into MCP-issued JWTs, maintaining trust boundaries. |
| Public clients w/ no secrets                | Enforced PKCE (S256) for all clients.                                            |
| Token delegation and mapping                | `/exchange/spotify-token` securely maps Spotify tokens to MCP sessions.          |
| Scoped access for tools                     | Issued tokens carry `scope=mcp:tools`, enforcing least privilege.                |
| Key rotation & discovery                    | RSA key published via JWKS, supporting dynamic rotation.                         |

---

### 5. Token Lifecycle and Security

* **Short-lived access tokens** (15 mins)
* **Refresh token rotation** (revokes parent on use)
* **RFC 7009 `/revoke`** endpoint for logout
* **Spotify token exchange** endpoint for federated identity binding

```http
POST /token
grant_type=refresh_token
refresh_token=xyz123
```

---

## 🧩 Architecture

```
+--------------------------+
|   MCP Client (Tool)      |
|--------------------------|
|  /authorize (PKCE)       |
|  ↳ Redirect to Spotify   |
|  ↳ /spotify-callback     |
|  ↳ /token (MCP JWT)      |
+--------------------------+
              ^
              |
              v
+--------------------------+
|   MCP Auth Server        |
|--------------------------|
|  /register               |
|  /authorize              |
|  /token                  |
|  /exchange/spotify-token |
|  /revoke                 |
+--------------------------+
              ^
              |
              v
+--------------------------+
|   Spotify Web API        |
+--------------------------+
```

---

## 🛡️ Security Highlights

* ✅ PKCE (S256) enforcement — no client secrets
* ✅ RSA (RS256) signatures with JWKS endpoint
* ✅ Strict redirect URI validation
* ✅ Token rotation & replay protection
* ✅ OIDC discovery at `/.well-known/openid-configuration`
* ✅ Cached key metadata for verifiers

---

## 🧠 This project demonstrates:

* **Security-focused full-stack design**, with an emphasis on **identity, authentication, and observability**
* Integration of **OpenTelemetry and Azure Monitor** for distributed tracing and performance visibility
* Modular architecture — easily extendable for **GraphQL/REST tooling** 

```csharp
builder.Services.AddOpenTelemetry().UseAzureMonitor();
```

---

## 🔮 Future Enhancements

* [ ] Add OAuth 2.0 Introspection (RFC 7662)
* [ ] Implement JWKS key rotation scheduler
* [ ] Add structured audit logging for client registration events
* [ ] Integrate fine-grained MCP tool scopes
* [ ] Provide front-end OAuth client sample (React + TypeScript)

---

## 🧪 Running Locally

```bash
dotnet run
```

Visit:

* [`https://localhost:8080/.well-known/openid-configuration`](https://localhost:8080/.well-known/openid-configuration)
* [`https://localhost:8080/register`](https://localhost:8080/register)
* [`https://localhost:8080/authorize`](https://localhost:8080/authorize)

**Environment Variables**

```bash
jwt-kid="my-key-id"
jwt-pemPrivateKey="-----BEGIN PRIVATE KEY-----..."
env-issuer="https://localhost:8080"
```

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](./LICENSE) for details.

---

### 👏 Acknowledgements

* [Spotify Web API](https://developer.spotify.com/)
* [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
* [GoFastMCP Authentication Docs](https://gofastmcp.com/servers/auth/authentication)
* [RFC 7591 – Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
* [RFC 8414 – OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)

