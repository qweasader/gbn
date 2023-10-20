# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0169");
  script_cve_id("CVE-2023-24539", "CVE-2023-24540", "CVE-2023-29400");
  script_tag(name:"creation_date", value:"2023-05-17 04:13:46 +0000 (Wed, 17 May 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-22 18:22:00 +0000 (Mon, 22 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0169)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0169");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0169.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31886");
  script_xref(name:"URL", value:"https://groups.google.com/g/golang-announce/c/MEb0UyuSMsU");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-May/014738.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2023-0169 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Angle brackets (<>) were not considered dangerous characters when inserted
into CSS contexts. Templates containing multiple actions separated by a
'/' character could result in unexpectedly closing the CSS context and
allowing for injection of unexpected HMTL, if executed with untrusted
input. (CVE-2023-24539)
Not all valid JavaScript whitespace characters were considered to be
whitespace. Templates containing whitespace characters outside of the
character set '\t\n\f\r\u0020\u2028\u2029' in JavaScript contexts that
also contain actions may not be properly sanitized during execution.
(CVE-2023-24540)
Templates containing actions in unquoted HTML attributes (e.g.
'attr={{.}}') executed with empty input could result in output that would
have unexpected results when parsed due to HTML normalization rules. This
may allow injection of arbitrary attributes into tags. (CVE-2023-29400)");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.19.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.19.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.19.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.19.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-race", rpm:"golang-race~1.19.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.19.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.19.9~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.19.9~1.mga8", rls:"MAGEIA8"))) {
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
