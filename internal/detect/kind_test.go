package detect

import (
	"strings"
	"testing"

	"github.com/kiaamaaio/logscrub/internal/label"
)

func TestParseTypes(t *testing.T) {
	def := KindSet(0).With(KindEmail).With(KindIPv4).With(KindIPv6).With(KindSecret)
	aws := KindSet(0).With(KindAWSAccount).With(KindAWSS3Bucket).With(KindAWSHost)
	tests := []struct {
		spec string
		want KindSet
	}{
		{"default", def},
		{"email", KindSet(0).With(KindEmail)},
		{"ipv4", KindSet(0).With(KindIPv4)},
		{"ipv6", KindSet(0).With(KindIPv6)},
		{"ipv4,ipv6", KindSet(0).With(KindIPv4).With(KindIPv6)},
		{"secret", KindSet(0).With(KindSecret)},
		{"uuid", KindSet(0).With(KindUUID)},
		{"default,uuid", def.With(KindUUID)},
		{"uuid,default", def.With(KindUUID)},
		{"email,email", KindSet(0).With(KindEmail)},
		{"email,default", def},
		{"email,uuid", KindSet(0).With(KindEmail).With(KindUUID)},
		{"aws_account", KindSet(0).With(KindAWSAccount)},
		{"aws_s3_bucket", KindSet(0).With(KindAWSS3Bucket)},
		{"aws", aws},
		{"cloud", aws},
		{"aws,cloud", aws},
		{"default,aws", def | aws},
		{"aws,default", def | aws},
		{"default,cloud", def | aws},
		{"aws_account,default", def.With(KindAWSAccount)},
		{"default,uuid,aws", def.With(KindUUID) | aws},
		{"email,aws_s3_bucket", KindSet(0).With(KindEmail).With(KindAWSS3Bucket)},
	}
	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			got, err := ParseTypes(tt.spec)
			if err != nil {
				t.Fatalf("ParseTypes(%q): %v", tt.spec, err)
			}
			if got != tt.want {
				t.Errorf("ParseTypes(%q) = %b, want %b", tt.spec, got, tt.want)
			}
		})
	}
}

// 受け入れ基準: 存在しない種別名を指定するとエラー終了する。
// 仕様に書かれた種別名と完全に一致しないものは、すべて存在しない種別名として扱う。
func TestParseTypesRejectsUnknown(t *testing.T) {
	for _, spec := range []string{
		"", "foo", "email,foo", "foo,email", "Email", "EMAIL", " email", "email ", "email, uuid",
		"email,", ",email", "email,,uuid", "all", "ip", "ipv", "phone_jp", "postal_jp", "credit_card", "my_number", "base64", "custom",
		"ipv4_global", "default,", "defaults",
		"AWS", "Aws", "aws_", "aws_*", "aws_hosts", "aws_account_id", "s3", "aws-account", "clouds", "gcp", " aws", "aws,",
	} {
		t.Run(spec, func(t *testing.T) {
			if _, err := ParseTypes(spec); err == nil {
				t.Errorf("ParseTypes(%q) succeeded, want error", spec)
			}
		})
	}
}

func TestParseTypesErrorNamesTheUnknownTypeAndTheValidOnes(t *testing.T) {
	_, err := ParseTypes("email,phone_jp")
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"phone_jp", "default", "aws", "cloud", "email", "ipv4", "ipv6", "secret", "uuid", "aws_account", "aws_s3_bucket"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestDefaultKinds(t *testing.T) {
	for _, k := range []Kind{KindEmail, KindIPv4, KindIPv6, KindSecret} {
		if !DefaultKinds.Has(k) {
			t.Errorf("DefaultKinds lacks %v", k)
		}
	}
	for _, k := range []Kind{KindUUID, KindAWSAccount, KindAWSS3Bucket, KindAWSHost} {
		if DefaultKinds.Has(k) {
			t.Errorf("DefaultKinds has %v; it is disabled by default", k)
		}
	}
}

// 種別の表の性質(仕様 4 章): 種別名は重複せず、クラウドの種別は `<クラウド>_` で始まり、
// 既定で有効の種別はクラウドの種別でない。並びは、共通の種別のあとに、クラウドごとにまとめる。
func TestTypesTable(t *testing.T) {
	want := []string{"email", "ipv4", "ipv6", "secret", "uuid", "aws_account", "aws_s3_bucket", "aws_host"}
	var got []string
	seen := map[string]bool{}
	for i, ti := range Types {
		got = append(got, ti.Name())
		if seen[ti.Name()] {
			t.Errorf("duplicate type %q", ti.Name())
		}
		seen[ti.Name()] = true
		if ti.Cloud != "" && !strings.HasPrefix(ti.Name(), ti.Cloud+"_") {
			t.Errorf("%q does not start with its cloud %q", ti.Name(), ti.Cloud)
		}
		if ti.Cloud == "" && strings.Contains(ti.Name(), "_") {
			t.Errorf("%q looks like a cloud type but has no cloud", ti.Name())
		}
		if ti.Cloud != "" && ti.Default {
			t.Errorf("cloud type %q is enabled by default", ti.Name())
		}
		if i > 0 && Types[i-1].Cloud != "" && ti.Cloud != Types[i-1].Cloud {
			for _, prev := range Types[:i] {
				if prev.Cloud == ti.Cloud {
					t.Errorf("types of cloud %q are not grouped together", ti.Cloud)
				}
			}
		}
		if ti.Kind.String() != ti.Name() || int(ti.Kind) >= 32 {
			t.Errorf("Kind %d: name %q", ti.Kind, ti.Name())
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("Types = %q, want %q", got, want)
	}
}

// まとまりの中身は、表から求めたものと一致する(仕様 4 章「対象種別の指定」)。
//   - aws: `aws_` で始まるすべての種別。cloud: すべてのクラウドの種別
func TestGroups(t *testing.T) {
	var names []string
	byName := map[string]KindSet{}
	for _, g := range Groups {
		names = append(names, g.Name)
		byName[g.Name] = g.Kinds
		for _, ti := range Types {
			if g.Name == ti.Name() {
				t.Errorf("group %q has the same name as a type", g.Name)
			}
		}
	}
	if strings.Join(names, ",") != "default,aws,cloud" {
		t.Errorf("groups = %q", names)
	}
	var aws, cloud KindSet
	for _, ti := range Types {
		if strings.HasPrefix(ti.Name(), "aws_") {
			aws = aws.With(ti.Kind)
		}
		if ti.Cloud != "" {
			cloud = cloud.With(ti.Kind)
		}
	}
	if aws != KindSet(0).With(KindAWSAccount).With(KindAWSS3Bucket).With(KindAWSHost) {
		t.Errorf("aws_ types = %b", aws)
	}
	if byName["default"] != DefaultKinds || byName["aws"] != aws || byName["cloud"] != cloud {
		t.Errorf("groups = %v, want default %b, aws %b, cloud %b", Groups, DefaultKinds, aws, cloud)
	}
}

// KindSet は、すべての種別を、互いに区別して持てる。
func TestKindSetHoldsAllKinds(t *testing.T) {
	var all KindSet
	for _, ti := range Types {
		if all.Has(ti.Kind) {
			t.Errorf("%v collides with another kind", ti.Kind)
		}
		all = all.With(ti.Kind)
	}
	for _, ti := range Types {
		if !all.Has(ti.Kind) || KindSet(0).With(ti.Kind).Has(ti.Kind+1) {
			t.Errorf("%v is not held", ti.Kind)
		}
	}
}

func TestKindString(t *testing.T) {
	want := map[Kind]string{
		KindEmail: "email", KindIPv4: "ipv4", KindIPv6: "ipv6", KindSecret: "secret", KindUUID: "uuid",
		KindAWSAccount: "aws_account", KindAWSS3Bucket: "aws_s3_bucket", KindAWSHost: "aws_host",
	}
	for k, s := range want {
		if k.String() != s {
			t.Errorf("Kind(%d).String() = %q, want %q", k, k.String(), s)
		}
	}
}

func TestLabelType(t *testing.T) {
	tests := []struct {
		m    Match
		want string
	}{
		{Match{Kind: KindEmail}, "email"},
		{Match{Kind: KindSecret}, "secret"},
		{Match{Kind: KindUUID}, "uuid"},
		{Match{Kind: KindAWSAccount}, "aws_account"},
		{Match{Kind: KindAWSS3Bucket}, "aws_s3_bucket"},
		{Match{Kind: KindAWSHost}, "aws_host"},
		{Match{Kind: KindIPv4, Class: ClassGlobal}, "ipv4_global"},
		{Match{Kind: KindIPv4, Class: ClassPrivate}, "ipv4_private"},
		{Match{Kind: KindIPv6, Class: ClassGlobal}, "ipv6_global"},
		{Match{Kind: KindIPv6, Class: ClassPrivate}, "ipv6_private"},
		// 置換しないもの(特殊アドレス)や区別のない IP には、ラベルがない。
		{Match{Kind: KindIPv4, Class: ClassSpecial}, ""},
		{Match{Kind: KindIPv4}, ""},
		{Match{Kind: KindIPv6, Class: ClassNone}, ""},
	}
	for _, tt := range tests {
		if got := tt.m.LabelType(); got != tt.want {
			t.Errorf("%+v.LabelType() = %q, want %q", tt.m, got, tt.want)
		}
	}
}

// LabelType が返す値は、すべて label.Types にあり、label.Types はすべて LabelType で作れる。
func TestLabelTypesMatchLabelPackage(t *testing.T) {
	produced := map[string]bool{}
	for _, ti := range Types {
		k := ti.Kind
		for _, c := range []Class{ClassNone, ClassGlobal, ClassPrivate} {
			if s := (Match{Kind: k, Class: c}).LabelType(); s != "" {
				produced[s] = true
			}
		}
	}
	for _, typ := range label.Types {
		if !produced[typ] {
			t.Errorf("label.Types has %q but no Match produces it", typ)
		}
		delete(produced, typ)
	}
	for typ := range produced {
		t.Errorf("Match produces %q which is not in label.Types", typ)
	}
}

func TestParseUUIDVersions(t *testing.T) {
	tests := []struct {
		in   string
		want uint16
	}{
		{"4", 1 << 4},
		{"4,7", 1<<4 | 1<<7},
		{"7,4", 1<<4 | 1<<7},
		{"4,4", 1 << 4},
		{"1,2,3,4,5,6,7,8", 0xFF << 1},
		{"1", 1 << 1},
		{"8", 1 << 8},
	}
	for _, tt := range tests {
		got, err := ParseUUIDVersions(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseUUIDVersions(%q) = %b, %v; want %b", tt.in, got, err, tt.want)
		}
	}
	// 1〜8 以外は、エラー(仕様 4.2)。空の要素・空白・数字以外も、エラー。
	for _, in := range []string{"", "0", "9", "10", "a", "4,", ",4", "4,,7", " 4", "4 ", "-1", "4;7", "v4", "4.0", "０"} {
		if _, err := ParseUUIDVersions(in); err == nil {
			t.Errorf("ParseUUIDVersions(%q) succeeded, want error", in)
		}
	}
}

func TestParseScope(t *testing.T) {
	for in, want := range map[string]Scope{"all": ScopeAll, "global": ScopeGlobal, "private": ScopePrivate} {
		got, err := ParseScope(in)
		if err != nil || got != want {
			t.Errorf("ParseScope(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "ALL", "Global", "public", "all ", "g"} {
		if _, err := ParseScope(in); err == nil {
			t.Errorf("ParseScope(%q) succeeded, want error", in)
		}
	}
}
