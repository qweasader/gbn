# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0185");
  script_cve_id("CVE-2016-3698");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-14 00:23:59 +0000 (Tue, 14 Jun 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0185)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0185");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0185.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/05/17/9");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18477");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2016-1086.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libndp' package(s) announced via the MGASA-2016-0185 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libndp package fixes security vulnerability:

Libndp is a library (used by NetworkManager) that provides a wrapper for the
IPv6 Neighbor Discovery Protocol. It also provides a tool named ndptool for
sending and receiving NDP messages.

Security Fix(es):

It was found that libndp did not properly validate and check the origin of
Neighbor Discovery Protocol (NDP) messages. An attacker on a non-local network
could use this flaw to advertise a node as a router, allowing them to perform
man-in-the-middle attacks on a connecting client, or disrupt the network
connectivity of that client. (CVE-2016-3698)");

  script_tag(name:"affected", value:"'libndp' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ndp-devel", rpm:"lib64ndp-devel~1.4~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ndp0", rpm:"lib64ndp0~1.4~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndp", rpm:"libndp~1.4~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndp-devel", rpm:"libndp-devel~1.4~3.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libndp0", rpm:"libndp0~1.4~3.1.mga5", rls:"MAGEIA5"))) {
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
