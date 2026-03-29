---
title: Concepts
layout: default
nav_order: 2
has_children: true
has_toc: false
---

# Cross-cutting concepts

These pages cover principles and patterns that apply across all credential types. Read them before diving into the per-system remediation guides.

---

### Start here

| Concept | What you'll learn |
|---------|-------------------|
| [What "fully remediated" means](fully-remediated.md) | The target state for a clean workstation and how to verify you've reached it |
| [Tier definitions](tier-definitions.md) | The Eliminate / Vault / Reduce blast radius framework used in every guide |

### Patterns and tradeoffs

| Concept | What you'll learn |
|---------|-------------------|
| [The orphaned file anti-pattern](orphaned-files.md) | Why credentials reappear after remediation and how to prevent it |
| [Workflow friction ranking](workflow-friction.md) | Which remediation approaches slow developers down the most, ranked by daily impact |
| [CI/CD implications](cicd-matrix.md) | What breaks in your pipelines when you remove local keys, and what to migrate to |

### Tool assessments

| Tool | What you'll learn |
|------|-------------------|
| [1Password CLI](1password-cli.md) | Assessment as a universal Tier 2 (vault) solution across all credential types |
| [macOS Keychain](macos-keychain.md) | Assessment as a free, built-in Tier 2 option and where it falls short |
