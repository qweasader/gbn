# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0128");
  script_cve_id("CVE-2023-45288");
  script_tag(name:"creation_date", value:"2024-04-15 04:26:26 +0000 (Mon, 15 Apr 2024)");
  script_version("2024-04-15T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-04-15 05:05:35 +0000 (Mon, 15 Apr 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2024-0128)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0128");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0128.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33068");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/04/05/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang' package(s) announced via the MGASA-2024-0128 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-45288: An attacker may cause an HTTP/2 endpoint to read
arbitrary amounts of header data by sending an excessive number of
CONTINUATION frames. Maintaining HPACK state requires parsing and
processing all HEADERS and CONTINUATION frames on a connection. When a
request's headers exceed MaxHeaderBytes, no memory is allocated to store
the excess headers, but they are still parsed. This permits an attacker
to cause an HTTP/2 endpoint to read arbitrary amounts of header data,
all associated with a request which is going to be rejected. These
headers can include Huffman-encoded data which is significantly more
expensive for the receiver to decode than for an attacker to send. The
fix sets a limit on the amount of excess header frames we will process
before closing a connection.");

  script_tag(name:"affected", value:"'golang' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.21.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-bin", rpm:"golang-bin~1.21.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-docs", rpm:"golang-docs~1.21.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-misc", rpm:"golang-misc~1.21.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-shared", rpm:"golang-shared~1.21.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.21.9~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-tests", rpm:"golang-tests~1.21.9~1.mga9", rls:"MAGEIA9"))) {
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
