# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131212");
  script_cve_id("CVE-2015-7575", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0475", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"creation_date", value:"2016-02-08 17:55:18 +0000 (Mon, 08 Feb 2016)");
  script_version("2023-06-20T05:05:20+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:20 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0048)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0048");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0048.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17576");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixJAVA");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2016-0049.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'copy-jdk-configs, java-1.8.0-openjdk, lua-lunit, lua-posix' package(s) announced via the MGASA-2016-0048 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write flaw was found in the JPEG image format decoder in
the AWT component in OpenJDK. A specially crafted JPEG image could cause
a Java application to crash or, possibly execute arbitrary code. An
untrusted Java application or applet could use this flaw to bypass Java
sandbox restrictions (CVE-2016-0483).

An integer signedness issue was found in the font parsing code in the 2D
component in OpenJDK. A specially crafted font file could possibly cause
the Java Virtual Machine to execute arbitrary code, allowing an untrusted
Java application or applet to bypass Java sandbox restrictions
(CVE-2016-0494).

It was discovered that the password-based encryption (PBE) implementation
in the Libraries component in OpenJDK used an incorrect key length. This
could, in certain cases, lead to generation of keys that were weaker than
expected (CVE-2016-0475).

It was discovered that the JAXP component in OpenJDK did not properly
enforce the totalEntitySizeLimit limit. An attacker able to make a Java
application process a specially crafted XML file could use this flaw to
make the application consume an excessive amount of memory
(CVE-2016-0466).

A flaw was found in the way TLS 1.2 could use the MD5 hash function for
signing ServerKeyExchange and Client Authentication packets during a TLS
handshake. A man-in-the-middle attacker able to force a TLS connection to
use the MD5 hash function could use this flaw to conduct collision attacks
to impersonate a TLS server or an authenticated TLS client
(CVE-2015-7575).

Multiple flaws were discovered in the Networking and JMX components in
OpenJDK. An untrusted Java application or applet could use these flaws to
bypass certain Java sandbox restrictions (CVE-2016-0402, CVE-2016-0448).

This update also required the addition of a new package, copy-jdk-configs,
and a patch to the chkconfig package which adds the --family option to the
alternatives command. Both of these are used by scriplets in the update
java-1.8.0-openjdk packages.");

  script_tag(name:"affected", value:"'copy-jdk-configs, java-1.8.0-openjdk, lua-lunit, lua-posix' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"copy-jdk-configs", rpm:"copy-jdk-configs~1.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.72~1.b15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.72~1.b15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.72~1.b15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.72~1.b15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.72~1.b15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.72~1.b15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.72~1.b15.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-lunit", rpm:"lua-lunit~0.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-posix", rpm:"lua-posix~33.3.1~1.mga5", rls:"MAGEIA5"))) {
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
