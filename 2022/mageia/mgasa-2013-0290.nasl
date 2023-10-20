# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0290");
  script_cve_id("CVE-2013-0169", "CVE-2013-1621", "CVE-2013-4623");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2013-0290)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0290");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0290.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11275");
  script_xref(name:"URL", value:"https://polarssl.org/tech-updates/security-advisories/polarssl-security-advisory-2013-01");
  script_xref(name:"URL", value:"https://polarssl.org/tech-updates/security-advisories/polarssl-security-advisory-2013-03");
  script_xref(name:"URL", value:"https://polarssl.org/tech-updates/releases/polarssl-1.2.6-released");
  script_xref(name:"URL", value:"https://polarssl.org/tech-updates/releases/polarssl-1.2.7-released");
  script_xref(name:"URL", value:"https://polarssl.org/tech-updates/releases/polarssl-1.2.8-released");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115922.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polarssl' package(s) announced via the MGASA-2013-0290 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The TLS protocol 1.1 and 1.2 and the DTLS protocol 1.0 and 1.2, as used
in PolarSSL before 1.2.6, does not properly consider timing side-channel
attacks on a MAC check requirement during the processing of malformed CBC
padding, which allows remote attackers to conduct distinguishing attacks
and plaintext-recovery attacks via statistical analysis of timing data for
crafted packets, aka the 'Lucky Thirteen' issue (CVE-2013-0169).

Array index error in the SSL module in PolarSSL before 1.2.6 might allow
remote attackers to cause a denial of service via vectors involving a
crafted padding-length value during validation of CBC padding in a TLS
session (CVE-2013-1621).

A third party can set up a SSL/TLS handshake with a server and send a
malformed Certificate handshake message that results in an infinite loop
for that connection. With a Man-in-the-Middle attack on a client, a third
party can trigger the same infinite loop on a client (CVE-2013-4623).");

  script_tag(name:"affected", value:"'polarssl' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl-devel", rpm:"lib64polarssl-devel~1.2.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64polarssl2", rpm:"lib64polarssl2~1.2.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl-devel", rpm:"libpolarssl-devel~1.2.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpolarssl2", rpm:"libpolarssl2~1.2.8~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polarssl", rpm:"polarssl~1.2.8~1.mga3", rls:"MAGEIA3"))) {
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
