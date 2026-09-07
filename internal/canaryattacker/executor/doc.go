// Package executor implements CanaryAttacker's closed, externally bounded
// tool policy and execution boundary. It can reach only explicitly bound
// private laboratory targets; model-facing code cannot supply a URL, address,
// credential value, header, shell command, filesystem path, or control-plane
// operation through this package.
package executor
