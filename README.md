# Seeing Through the Fog: Interpreting Entra ID Signals During AiTM Attacks

This repository contains hunting queries and additional content from the **FIRST Conference 2026 (FirstCon 26)** session *"Seeing Through the Fog: Interpreting Entra ID Signals During AiTM Attacks"*.

## About

Adversary-in-the-Middle (AiTM) attacks continue to evolve, making it critical for defenders to understand and interpret the signals available in Microsoft Entra ID. This session explored practical techniques for detecting and investigating AiTM activity using Entra ID logs and related telemetry.

## Repository Contents

- [**Hunting Queries**](QUERIES.md) – /Almost/ ready-to-use queries for detecting AiTM attack patterns in your environment.
- **Additional Resources** – Supplementary materials and references shared during the session.

## 🧜‍♀️ Go with the flow 


```mermaid
flowchart TD
    A["Blocked by CAP?"]

    A -->|No| B["Did the user complete MFA?"]
    A -->|Yes| D["Did the user complete MFA?"]

    B -->|Yes| C[Treat as Compromised User]
    B -->|No| D[Password is still compromised]

    C --> E[Revoke active sessions]
    C --> F[Force password reset]
    C --> G[Investigate user activity]

    G --> H[Monitor non-CAE tokens]
    G --> I[Review data access to assess impact]

    D --> J[Force password reset]
    D --> K["Can the password be used to access other entry points?"]

    K --> L[Check other remote access paths]
```


## Disclaimer

These queries are provided as-is for educational and defensive purposes. Always validate and tune them for your specific environment before using in production.
