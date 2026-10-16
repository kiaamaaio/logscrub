package cli

// usageTop は、全体の使い方。
const usageTop = `Usage:
  logscrub mask    [FILE ...] [options]
  logscrub restore --source FILE [--source FILE ...] [ANSWER_FILE] [options]
  logscrub types   [--verbose]

mask replaces email addresses, IP addresses, tokens, UUIDs and AWS values
(account IDs, S3 bucket names) in text with labels such as <email_1> (or with
keyed hashes). restore puts the original values back into text (for example
an AI's answer) that contains such labels. The text is read from FILE (stdin
when FILE is omitted or "-") and written to stdout.

Run "logscrub <command> --help" for the options of a command.
`

// secretFormatsHelp は、secret の対応形式(仕様 4.1)。`types --verbose` と、`mask --help` に出す。
const secretFormatsHelp = `Supported secret formats:
  AWS access key ID     AKIA or ASIA + 16 uppercase letters or digits
  AWS signature (SigV4) exactly 64 lowercase hex digits after X-Amz-Signature= or
                        Signature= (presigned URLs, AWS4-HMAC-SHA256 Authorization)
  GitHub                ghp_ gho_ ghu_ ghs_ ghr_ + 36 or more alphanumerics;
                        github_pat_ + 22 or more alphanumerics or _
  Slack                 xoxb- xoxp- xoxa- xoxr- xoxs- + 10 or more alphanumerics or -
  Stripe                sk_live_ sk_test_ rk_live_ rk_test_ + 24 or more alphanumerics
  Google API key        AIza + 35 alphanumerics, - or _
  sk- API key           sk- + 20 or more alphanumerics, - or _
  JWT                   eyJ... . eyJ... . ... (three parts)
  Authorization header  the credentials after "Bearer " or "Basic ", when they are the
                        value of Authorization or of one of the key names below
  Key-based             the value of password, passwd, secret, token, api_key, apikey,
                        access_key, private_key, client_secret, access_token,
                        refresh_token, auth_token, session_id (case-insensitive;
                        "-", "_", "." and camelCase boundaries separate words;
                        key=value, key: value, "key": "value")
Tokens in any other format are not detected.
`

const usageMask = `Usage: logscrub mask [FILE ...] [options]

Replace email addresses, IP addresses, tokens, UUIDs and AWS values in FILE
(stdin when omitted or "-") with labels or hashes. Several FILEs are read in
the given order as one input (numbering continues across files).

Options (they may be written before or after FILE):
  --mode mask|hash          mask: <email_1> style labels (default).
                            hash: <type>_<hex> using HMAC-SHA256; cannot be restored.
  --types LIST              comma separated types: email, ipv4, ipv6, secret, uuid,
                            aws_account, aws_s3_bucket; or groups: default, aws,
                            cloud. Only the listed types are replaced (add
                            "default" to keep the default ones). Default: default
                            (email, ipv4, ipv6, secret; uuid and aws_* are off).
                            Run "logscrub types" for the list.
  --uuid-versions 4,7       replace only these UUID versions (1-8); enables uuid.
  --ip-scope all|global|private
                            which IP addresses to replace (default: all).
  --allow VALUE             never replace this exact value (repeatable).
  --mask-format FMT         label format containing {type} and {n} once each
                            (default: <{type}_{n}>).
  --email-hash full|local   hash mode: hash the whole address (email_<hex>, default)
                            or only the local part (hash_<hex>@domain).
  --hash-length N           hash mode: number of hex digits, 8 to 64 (default 12).
  --key-file FILE           hash mode: read the key from FILE instead of the
                            LOGSCRUB_KEY environment variable.
  --stats                   print the number of replacements per type to stderr.
  --fail-on-detect          exit with status 2 when something was replaced.
  -o, --output FILE         write to FILE instead of stdout.
  -h, --help                show this help.

Exit status: 0 success, 1 error, 2 something was replaced (--fail-on-detect).

` + secretFormatsHelp

const usageRestore = `Usage: logscrub restore --source FILE [--source FILE ...] [ANSWER_FILE] [options]

Replace the labels in ANSWER_FILE (stdin when omitted or "-") with the original
values. The mapping is rebuilt from the --source files, which must be the same
input, in the same order, that was given to "logscrub mask" with the same
detection options. Nothing is written to disk besides the output.

Options (they may be written before or after ANSWER_FILE):
  --source FILE             the input given to mask (required, repeatable;
                            "-" is stdin and needs an ANSWER_FILE).
  --types LIST              same as mask.
  --uuid-versions 4,7       same as mask.
  --ip-scope all|global|private
                            same as mask.
  --allow VALUE             same as mask (repeatable).
  --mask-format FMT         same as mask.
  -o, --output FILE         write to FILE instead of stdout.
  -h, --help                show this help.

Labels that cannot be restored are left as they are and listed on stderr;
the exit status is still 0. Output of "mask --mode hash" cannot be restored.
`

const usageTypes = `Usage: logscrub types [--verbose]

List the types that can be given to --types.

Options:
  --verbose   also list the supported secret formats.
  -h, --help  show this help.
`
