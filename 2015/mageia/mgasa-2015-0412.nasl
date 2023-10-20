# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131101");
  script_cve_id("CVE-2015-4734", "CVE-2015-4803", "CVE-2015-4805", "CVE-2015-4806", "CVE-2015-4835", "CVE-2015-4840", "CVE-2015-4842", "CVE-2015-4843", "CVE-2015-4844", "CVE-2015-4860", "CVE-2015-4868", "CVE-2015-4872", "CVE-2015-4881", "CVE-2015-4882", "CVE-2015-4883", "CVE-2015-4893", "CVE-2015-4903", "CVE-2015-4911");
  script_tag(name:"creation_date", value:"2015-10-26 07:35:59 +0000 (Mon, 26 Oct 2015)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2015-0412)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0412");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0412.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16998");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html#AppendixJAVA");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-1919.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk' package(s) announced via the MGASA-2015-0412 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated java-1.8.0-openjdk packages fix security vulnerabilities:

Multiple flaws were discovered in the CORBA, Libraries, RMI, Serialization,
and 2D components in OpenJDK. An untrusted Java application or applet could
use these flaws to completely bypass Java sandbox restrictions
(CVE-2015-4835, CVE-2015-4881, CVE-2015-4843, CVE-2015-4883, CVE-2015-4860,
CVE-2015-4805, CVE-2015-4844).

Multiple denial of service flaws were found in the JAXP component in
OpenJDK. A specially crafted XML file could cause a Java application using
JAXP to consume an excessive amount of CPU and memory when parsed
(CVE-2015-4803, CVE-2015-4893, CVE-2015-4911).

A flaw was found in the way the Libraries component in OpenJDK handled
certificate revocation lists (CRL). In certain cases, CRL checking code
could fail to report a revoked certificate, causing the application to
accept it as trusted (CVE-2015-4868).

It was discovered that the Security component in OpenJDK failed to properly
check if a certificate satisfied all defined constraints. In certain cases,
this could cause a Java application to accept an X.509 certificate which
does not meet requirements of the defined policy (CVE-2015-4872).

Multiple flaws were found in the Libraries, 2D, CORBA, JAXP, JGSS, and RMI
components in OpenJDK. An untrusted Java application or applet could use
these flaws to bypass certain Java sandbox restrictions (CVE-2015-4806,
CVE-2015-4840, CVE-2015-4882, CVE-2015-4842, CVE-2015-4734, CVE-2015-4903).");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.65~1.b17.1.mga5", rls:"MAGEIA5"))) {
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
