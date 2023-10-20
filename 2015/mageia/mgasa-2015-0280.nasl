# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.130098");
  script_cve_id("CVE-2015-2590", "CVE-2015-2601", "CVE-2015-2621", "CVE-2015-2625", "CVE-2015-2628", "CVE-2015-2632", "CVE-2015-2659", "CVE-2015-2808", "CVE-2015-3149", "CVE-2015-4000", "CVE-2015-4731", "CVE-2015-4732", "CVE-2015-4733", "CVE-2015-4748", "CVE-2015-4749", "CVE-2015-4760");
  script_tag(name:"creation_date", value:"2015-10-15 07:42:40 +0000 (Thu, 15 Oct 2015)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0280)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0280");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0280.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16387");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1207101#c11");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1223211#c33");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2015-1228.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk' package(s) announced via the MGASA-2015-0280 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws were discovered in the 2D, CORBA, JMX, Libraries and RMI
components in OpenJDK. An untrusted Java application or applet could use
these flaws to bypass Java sandbox restrictions (CVE-2015-4760,
CVE-2015-2628, CVE-2015-4731, CVE-2015-2590, CVE-2015-4732,
CVE-2015-4733).

A flaw was found in the way the Libraries component of OpenJDK verified
Online Certificate Status Protocol (OCSP) responses. An OCSP response with
no nextUpdate date specified was incorrectly handled as having unlimited
validity, possibly causing a revoked X.509 certificate to be interpreted
as valid (CVE-2015-4748).

It was discovered that the JCE component in OpenJDK failed to use constant
time comparisons in multiple cases. An attacker could possibly use these
flaws to disclose sensitive information by measuring the time used to
perform operations using these non-constant time comparisons
(CVE-2015-2601).

It was discovered that the GCM (Galois Counter Mode) implementation in
the Security component of OpenJDK failed to properly perform a null check.
This could cause the Java Virtual Machine to crash when an application
performed encryption using a block cipher in the GCM mode (CVE-2015-2659).

A flaw was found in the RC4 encryption algorithm. When using certain keys
for RC4 encryption, an attacker could obtain portions of the plain text
from the cipher text without the knowledge of the encryption key
(CVE-2015-2808).

Note: With this update, OpenJDK now disables RC4 TLS/SSL cipher suites by
default to address the CVE-2015-2808 issue. Refer to Red Hat Bugzilla bug
1207101, linked to in the References section, for additional details about
this change.

A flaw was found in the way the TLS protocol composed the Diffie-Hellman
(DH) key exchange. A man-in-the-middle attacker could use this flaw to
force the use of weak 512 bit export-grade keys during the key exchange,
allowing them do decrypt all traffic (CVE-2015-4000).

Note: This update forces the TLS/SSL client implementation in OpenJDK to
reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Refer to Red Hat Bugzilla bug 1223211,
linked to in the References section, for additional details about this
change.

It was discovered that the JNDI component in OpenJDK did not handle DNS
resolutions correctly. An attacker able to trigger such DNS errors could
cause a Java application using JNDI to consume memory and CPU time, and
possibly block further DNS resolution (CVE-2015-4749).

Multiple information leak flaws were found in the JMX and 2D components in
OpenJDK. An untrusted Java application or applet could use this flaw to
bypass certain Java sandbox restrictions (CVE-2015-2621, CVE-2015-2632).

A flaw was found in the way the JSSE component in OpenJDK performed X.509
certificate identity verification when establishing a TLS/SSL connection
to a host identified by an IP address. In certain cases, ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.51~1.b16.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.51~1.b16.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.51~1.b16.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.51~1.b16.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.51~1.b16.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.51~1.b16.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.51~1.b16.1.mga5", rls:"MAGEIA5"))) {
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
