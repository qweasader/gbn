# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856314");
  script_version("2024-07-25T05:05:41+0000");
  script_cve_id("CVE-2023-45142", "CVE-2024-22189");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-18 18:27:50 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"creation_date", value:"2024-07-23 04:00:33 +0000 (Tue, 23 Jul 2024)");
  script_name("openSUSE: Security Advisory for caddy (openSUSE-SU-2024:0211-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0211-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4POHOO6U2FW5XKZT7HPGZAJF7LQQW3W4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'caddy'
  package(s) announced via the openSUSE-SU-2024:0211-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for caddy fixes the following issues:

     Update to version 2.8.4:

  * cmd: fix regression in auto-detect of Caddyfile (#6362)

  * Tag v2.8.3 was mistakenly made on the v2.8.2 commit and is skipped

     Update to version 2.8.2:

  * cmd: fix auto-detetction of .caddyfile extension (#6356)

  * caddyhttp: properly sanitize requests for root path (#6360)

  * caddytls: Implement certmagic.RenewalInfoGetter

     Update to version 2.8.1:

  * caddyhttp: Fix merging consecutive `client_ip` or `remote_ip` matchers
         (#6350)

  * core: MkdirAll appDataDir in InstanceID with 0o700 (#6340)

     Update to version 2.8.0:

  * acmeserver: Add `sign_with_root` for Caddyfile (#6345)

  * caddyfile: Reject global request matchers earlier (#6339)

  * core: Fix bug in AppIfConfigured (fix #6336)

  * fix a typo (#6333)

  * autohttps: Move log WARN to INFO, reduce confusion (#6185)

  * reverseproxy: Support HTTP/3 transport to backend (#6312)

  * context: AppIfConfigured returns error  consider not-yet-provisioned
         modules (#6292)

  * Fix lint error about deprecated method in
         smallstep/certificates/authority

  * go.mod: Upgrade dependencies

  * caddytls: fix permission requirement with AutomationPolicy (#6328)

  * caddytls: remove ClientHelloSNICtxKey (#6326)

  * caddyhttp: Trace individual middleware handlers (#6313)

  * templates: Add `pathEscape` template function and use it in file
         browser (#6278)

  * caddytls: set server name in context (#6324)

  * chore: downgrade minimum Go version in go.mod (#6318)

  * caddytest: normalize the JSON config (#6316)

  * caddyhttp: New experimental handler for intercepting responses (#6232)

  * httpcaddyfile: Set challenge ports when http_port or https_port are
         used

  * logging: Add support for additional logger filters other than hostname
         (#6082)

  * caddyhttp: Log 4xx as INFO  5xx as ERROR (close #6106)

  * caddyhttp: Alter log message when request is unhandled (close #5182)

  * reverseproxy: Pointer to struct when loading modules  remove
         LazyCertPool (#6307)

  * tracing: add trace_id var (`http.vars.trace_id` placeholder) (#6308)

  * go.mod: CertMagic v0.21.0

  * reverseproxy: Implement health_follow_redirects (#6302)

  * caddypki: Allow use of root CA without a key. Fixes #6290 (#6298)

  * go.mod: Upgrade to quic-go v0.43.1

  * reverseproxy: HTTP transport: fix PROXY protocol initialization (#6301)

  * ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'caddy' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSEBackportsSLE-15-SP5") {

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-bash-completion", rpm:"caddy-bash-completion~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-fish-completion", rpm:"caddy-fish-completion~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-zsh-completion", rpm:"caddy-zsh-completion~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy", rpm:"caddy~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-bash-completion", rpm:"caddy-bash-completion~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-fish-completion", rpm:"caddy-fish-completion~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caddy-zsh-completion", rpm:"caddy-zsh-completion~2.8.4~bp155.2.3.1", rls:"openSUSEBackportsSLE-15-SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);