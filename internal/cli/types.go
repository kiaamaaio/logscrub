package cli

import (
	"fmt"
	"strings"
)

// typeEntry は、`logscrub types` の 1 行。
type typeEntry struct {
	id, onByDefault, description string
}

var typeEntries = []typeEntry{
	{"email", "on", "email addresses"},
	{"ipv4", "on", "IPv4 addresses (labels: ipv4_global, ipv4_private; special addresses are kept)"},
	{"ipv6", "on", "IPv6 addresses (labels: ipv6_global, ipv6_private; special addresses are kept)"},
	{"secret", "on", "tokens and credentials (see --verbose for the formats)"},
	{"uuid", "off", "UUIDs, versions 1-8 (enable with --types default,uuid or --uuid-versions)"},
}

func runTypes(e *env, args []string) int {
	fs := newFlagSet("types")
	verbose := fs.Bool("verbose", false, "also list the secret formats")
	_, code, done := e.parseFlags("types", usageTypes, fs, args)
	if done {
		return code
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-8s%-9s%s\n", "type", "default", "description")
	for _, t := range typeEntries {
		fmt.Fprintf(&sb, "%-8s%-9s%s\n", t.id, t.onByDefault, t.description)
	}
	sb.WriteString("\n\"default\" in --types stands for email, ipv4, ipv6 and secret.\n")
	if *verbose {
		sb.WriteString("\n")
		sb.WriteString(secretFormatsHelp)
	}
	fmt.Fprint(e.stdout, sb.String())
	return exitOK
}
