// Command canaryctl is the operator CLI: configure strictness and sting floor,
// define trust zones, inspect per-scope calibration status, submit feedback
// labels, and operate the deployment-wide enforcement KILL-SWITCH. See
// docs/ENGINE.md and docs/SCOPE.md.
//
// SUBCOMMAND DISPATCH: this is the FIRST git-style subcommand dispatcher in the
// repo. os.Args[1] selects the subcommand group (e.g. "killswitch"); each group
// owns its own action dispatch and parses its flags with a dedicated
// flag.NewFlagSet (stdlib `flag` only — the repo has no CLI-framework deps).
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "killswitch":
		// killswitch owns its own action dispatch (engage|revive|status) and parses
		// each action's flags from os.Args[3:].
		runKillSwitch(os.Args[2:])
	case "deviant":
		// deviant owns its own action dispatch (suppress|unsuppress|ack) and parses
		// each action's flags from os.Args[3:]. Same loopback admin + token as killswitch.
		runDeviant(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "canaryctl: unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	// TODO: subcommands: config, scope, status, feedback.
}

func usage() {
	fmt.Fprint(os.Stderr, `canaryctl — CanarySting operator CLI

Usage:
  canaryctl <subcommand> [action] [flags]

Subcommands:
  killswitch engage     halt enforcement deployment-wide (DISARM)
  killswitch revive     resume enforcement
  killswitch status     report the current enforcement-disarm posture
  deviant suppress      hide a known-benign deviant pattern from the default list (still counted)
  deviant unsuppress    clear a deviant pattern's triage state (un-suppress / un-ack)
  deviant ack           mark a deviant pattern seen-but-keep-showing (badged, demoted)

Run "canaryctl killswitch -h" for the kill-switch flags, or "canaryctl deviant -h"
for the deviant-triage flags.
`)
}
