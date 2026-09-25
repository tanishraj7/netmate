# NETmate — Network Security Engineer Assistant

> **Turning network-security expertise into a reusable, searchable engineering workflow.**

NETmate is a network security incident-solution assistant designed to reduce the repetitive effort involved in diagnosing and resolving network infrastructure incidents.

Built during my internship with **BT Group's Network Security team**, NETmate captures recurring incident knowledge and converts it into structured, reusable engineering playbooks.

---

## The Problem

Network-security incidents often follow recurring patterns, but solving them can still require engineers to search through:

- Previous tickets
- Documentation
- CLI references
- Device-specific procedures
- Personal experience
- Rollback procedures

The problem isn't always *knowing what to do* — it's finding the **right information, in the right sequence, at the right time**.

NETmate was built to reduce that friction.

### Traditional Workflow

```text
Ticket
  ↓
Search documentation
  ↓
Search previous tickets
  ↓
Find relevant commands
  ↓
Verify the sequence
  ↓
Make the change
  ↓
Figure out rollback
```

### NETmate Workflow

```text
Ticket
  ↓
Identify incident
  ↓
Match playbook
  ↓
Understand the problem
  ↓
Pre-check
  ↓
Implement
  ↓
Validate
  ↓
Rollback if required
```

---

## Key Features

### Structured Incident Resolution

Engineers can provide structured information such as:

- Device
- Problem Type
- Source IP
- Destination IP
- Interface / Zone
- Port
- ACL Name / Number
- Device ID
- Protocol
- VIP / Virtual Server
- Pool Name
- SSL Profile
- Additional Ticket Context

NETmate uses these inputs to generate a solution tailored to the incident.

---

### Raw Ticket Analysis

Not every ticket arrives in a perfectly structured format.

NETmate provides a **Raw Ticket** mode where an engineer can paste the complete customer request and use it to identify the relevant incident scenario.

```text
Customer Request
       ↓
Raw Ticket
       ↓
Incident Matching
       ↓
Relevant Playbook
       ↓
Guided Solution
```

---

### 100+ Incident Playbooks

NETmate contains a structured knowledge base covering **100+ network-security incident scenarios**.

Examples include:

- ACL permit / deny changes
- NAT configuration
- IP whitelisting / blacklisting
- External server access
- VPN configuration
- VLAN-related requests
- SSL certificate installation / renewal
- F5 BIG-IP configuration
- Firewall changes
- Routing changes
- Object-group modifications
- TACACS
- AAA
- Authentication and authorization operations

The objective is not simply to store commands.

> **NETmate captures the reasoning, sequence, validation, and rollback behind the command.**

---

## Guided Solution Workflow

Every solution is structured around a controlled change-management workflow.

### 1. Conceptual Explanation

Explains:

- What the issue is
- Why the change is required
- What the proposed configuration will accomplish

### 2. Pre-Check

Commands used to:

- Inspect the existing configuration
- Confirm the current state
- Verify the reported issue
- Ensure the proposed change is appropriate

### 3. Preparation / Implementation

Commands required to implement the requested change in the correct sequence.

### 4. Validation

Commands and checks used to confirm that the change produced the expected result.

### 5. Rollback

Commands required to safely reverse the change if validation fails or the implementation needs to be reverted.

```text
┌─────────────────────────┐
│ Conceptual Explanation  │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│       Pre-Check         │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│   Implementation        │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│      Validation         │
└────────────┬────────────┘
             ↓
┌─────────────────────────┐
│       Rollback          │
└─────────────────────────┘
```

---

## CHECK Safety Framework

NETmate follows the **CHECK** approach used when handling network changes.

| Step | Principle |
|------|-----------|
| **C** | Confirm the request |
| **H** | Ensure the customer/request is authorized |
| **E** | Ensure you are working on the correct device |
| **C** | Comprehend the proposed change |
| **K** | Know the positive and negative impact |

The goal is simple:

> **Don't blindly execute a command just because it looks correct. Understand the change before making it.**

---

## Supported Infrastructure

### Cisco

NETmate supports workflows involving:

- Cisco ASA
- Cisco Firepower
- Access Control Lists
- NAT
- VPN
- VLAN
- Routing
- Object Groups
- TACACS
- AAA

### F5 BIG-IP LTM

NETmate includes workflows involving:

- Virtual Servers
- VIPs
- Pools
- Pool Members
- Nodes
- SSL Profiles
- SSL Certificates
- Load Balancing
- Pool configuration

---

## Example: F5 SSL Certificate Renewal

One of the workflows supported by NETmate is **SSL Certificate — Install / Renew** on F5 BIG-IP LTM.

Instead of providing a collection of commands without context, NETmate explains the required sequence:

```text
1. Install the new certificate
2. Install the matching private key
3. Update the client SSL profile
4. Save the system configuration
5. Validate the endpoint
```

### Why the sequence matters

The certificate and matching private key need to be installed before modifying the SSL profile.

The existing certificate is preserved during the installation process so that the configuration can be rolled back without unnecessarily reinstalling the previous certificate.

NETmate therefore provides both the **commands** and the **reasoning behind the commands**.

---

## Interface

NETmate provides two primary modes.

### Structured Mode

The engineer selects:

```text
Device
   ↓
Problem Type
   ↓
Network Details
   ↓
Ticket Context
   ↓
Generate Solution
```

The interface also provides field-level tooltips containing command references to help engineers determine the required values.

---

### Raw Ticket Mode

The engineer can paste a complete ticket or customer request:

```text
Raw Customer Request
        ↓
       Analyze
        ↓
Incident Identification
        ↓
Solution Playbook
```

This allows NETmate to work closer to the way real-world network incidents arrive.

---

## Architecture

At a high level, NETmate follows a knowledge-driven workflow:

```text
                         ┌─────────────────┐
                         │     Engineer    │
                         └────────┬────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
             Structured Input             Raw Ticket
                    │                           │
                    └─────────────┬─────────────┘
                                  ↓
                        ┌──────────────────┐
                        │ Request Analysis │
                        └────────┬─────────┘
                                 ↓
                       ┌────────────────────┐
                       │ Incident Matching  │
                       └─────────┬──────────┘
                                 ↓
                       ┌────────────────────┐
                       │  Playbook Lookup   │
                       └─────────┬──────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │    Solution Generator    │
                    └────────────┬─────────────┘
                                 ↓
              ┌──────────────────┼──────────────────┐
              ↓                  ↓                  ↓
         Explanation          Commands          Rollback
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 ↓
                         Final Solution
```

---

## Knowledge Base

The core of NETmate is its structured incident knowledge base.

Each playbook captures the operational context required to safely execute a change.

A typical playbook contains:

```text
Incident
│
├── Device
├── Problem Type
├── Required Inputs
├── Concept
├── Pre-Checks
├── Implementation
├── Validation
└── Rollback
```

This structure makes the knowledge:

- Reusable
- Searchable
- Maintainable
- Easier to expand
- Easier to transfer between engineers

---

## Design Philosophy

NETmate was built around three principles.

### 1. Reduce Repetition

If engineers repeatedly solve the same class of problem, the solution should become reusable knowledge instead of being rediscovered every time.

### 2. Preserve Context

A command without context can be dangerous.

NETmate provides the reasoning, prerequisites, checks, expected outcome, and rollback procedure around the command.

### 3. Make Experience Transferable

Experienced engineers naturally accumulate operational knowledge.

NETmate turns that experience into structured knowledge that can be reused by others.

> **Don't just automate the command. Capture the thinking behind it.**

---

## Impact

NETmate was created around a real operational workflow rather than as a standalone demonstration project.

It aims to:

- Reduce time spent searching for recurring solutions
- Standardize troubleshooting workflows
- Make operational knowledge easier to access
- Reduce dependency on individual engineers' memory
- Encourage pre-change validation
- Make rollback procedures explicit
- Simplify onboarding for engineers working with unfamiliar incident types

---

## What I Learned

Building NETmate changed how I think about automation.

Automation isn't always about replacing a complicated process with AI.

Sometimes the bigger opportunity is much simpler:

> **Find the repetitive friction, understand why it exists, and turn the knowledge behind it into a system.**

Instead of asking only:

> *"Can this be automated?"*

I started asking:

> *"What does an experienced person know here that the system could remember?"*

That became the core idea behind NETmate.

---

## Screenshots

### Structured Incident Input



### Generated Solution Output



---

## Project Highlights

| Metric | Details |
|--------|---------|
| **100+** | Network incident playbooks |
| **2+** | Major infrastructure platforms |
| **2** | Input modes — Structured & Raw Ticket |
| **5** | CHECK safety principles |
| **End-to-End** | Concept → Pre-check → Implementation → Validation → Rollback |

---

## Disclaimer

NETmate is an engineering guidance and knowledge-reuse tool.

Generated commands should always be reviewed and validated against the target environment before being applied to production infrastructure.

---

## Author

**Tanish Raj Singh**

Computer Science Engineer  
Software Development · AI · Network Security

Built during my internship with the **BT Group Network Security team**.