# test/integration/

Cross-layer integration tests. Empty for now.

Priority scenarios to cover first:
- A flow touching canaries escalates 0 -> 1 -> 2 -> 3 as the score crosses
  per-tier thresholds (docs/ENGINE.md).
- The socket-cookie join: a verdict computed at L7 enforces against the correct
  flow in the kernel, and never against a bystander (docs/IDENTITY.md).
- Scope isolation: learned state in scope A never affects scope B; unresolved
  identity refuses to start (docs/SCOPE.md).
- Sting budget: attrition stops at the configured ceiling (docs/STING.md).
