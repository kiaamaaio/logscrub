package cli

import (
	"fmt"
	"strings"

	"github.com/kiaamaaio/logscrub/internal/detect"
)

// typeDescriptions は、`logscrub types` の説明。種別の並び・既定・まとまりは、detect.Types と detect.Groups による。
var typeDescriptions = map[detect.Kind]string{
	detect.KindEmail:       "email addresses",
	detect.KindIPv4:        "IPv4 addresses (labels: ipv4_global, ipv4_private; special addresses are kept)",
	detect.KindIPv6:        "IPv6 addresses (labels: ipv6_global, ipv6_private; special addresses are kept)",
	detect.KindSecret:      "tokens and credentials (see --verbose for the formats)",
	detect.KindUUID:        "UUIDs, versions 1-8 (enable with --types default,uuid or --uuid-versions)",
	detect.KindAWSAccount:  "AWS account IDs in ARNs, ECR registries and SQS queue URLs",
	detect.KindAWSS3Bucket: "S3 bucket names in s3:// URLs, S3 endpoints and ARNs",
	detect.KindAWSHost:     "customer-specific part of AWS service host names (RDS, ELB, CloudFront, ...)",
}

// cloudTitles は、`logscrub types` で、クラウドの種別の前に出す見出し。
var cloudTitles = map[string]string{
	"aws": "AWS",
}

func runTypes(e *env, args []string) int {
	fs := newFlagSet("types")
	verbose := fs.Bool("verbose", false, "also list the secret formats")
	positional, code, done := e.parseFlags("types", usageTypes, fs, args)
	if done {
		return code
	}
	if len(positional) > 0 {
		fmt.Fprintf(e.stderr, "logscrub: types takes no arguments (got %q)\nRun \"logscrub types --help\" for usage.\n", positional[0])
		return exitError
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-15s%-9s%s\n", "type", "default", "description")
	cloud := ""
	for _, t := range detect.Types {
		if t.Cloud != cloud {
			cloud = t.Cloud
			fmt.Fprintf(&sb, "\n%s:\n", cloudTitles[cloud])
		}
		on := "off"
		if t.Default {
			on = "on"
		}
		fmt.Fprintf(&sb, "%-15s%-9s%s\n", t.Name(), on, typeDescriptions[t.Kind])
	}
	sb.WriteString("\nGroups for --types:\n")
	for _, g := range detect.Groups {
		var names []string
		for _, t := range detect.Types {
			if g.Kinds.Has(t.Kind) {
				names = append(names, t.Name())
			}
		}
		fmt.Fprintf(&sb, "  %-9s%s\n", g.Name, strings.Join(names, ", "))
	}
	if *verbose {
		sb.WriteString("\n")
		sb.WriteString(secretFormatsHelp)
	}
	fmt.Fprint(e.stdout, sb.String())
	return exitOK
}
