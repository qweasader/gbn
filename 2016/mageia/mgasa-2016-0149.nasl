# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131300");
  script_cve_id("CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3426", "CVE-2016-3427");
  script_tag(name:"creation_date", value:"2016-05-09 11:18:03 +0000 (Mon, 09 May 2016)");
  script_version("2024-10-23T05:05:58+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:58 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-27 19:23:19 +0000 (Thu, 27 Jun 2024)");

  script_name("Mageia: Security Advisory (MGASA-2016-0149)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0149");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0149.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18235");
  script_xref(name:"URL", value:"https://rhn.redhat.com/errata/RHSA-2016-0650.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.8.0-openjdk' package(s) announced via the MGASA-2016-0149 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated java-1.8.0-openjdk packages fix security vulnerabilities:

Multiple flaws were discovered in the Serialization and Hotspot components in
OpenJDK. An untrusted Java application or applet could use these flaws to
completely bypass Java sandbox restrictions (CVE-2016-0686, CVE-2016-0687).

It was discovered that the RMI server implementation in the JMX component in
OpenJDK did not restrict which classes can be deserialized when deserializing
authentication credentials. A remote, unauthenticated attacker able to connect
to a JMX port could possibly use this flaw to trigger deserialization flaws
(CVE-2016-3427).

It was discovered that the JAXP component in OpenJDK failed to properly handle
Unicode surrogate pairs used as part of the XML attribute values. Specially
crafted XML input could cause a Java application to use an excessive amount of
memory when parsed (CVE-2016-3425).

It was discovered that the GCM (Galois/Counter Mode) implementation in the JCE
component in OpenJDK used a non-constant time comparison when comparing GCM
authentication tags. A remote attacker could possibly use this flaw to
determine the value of the authentication tag (CVE-2016-3426).

It was discovered that the Security component in OpenJDK failed to check the
digest algorithm strength when generating DSA signatures. The use of a digest
weaker than the key strength could lead to the generation of signatures that
were weaker than expected (CVE-2016-0695).");

  script_tag(name:"affected", value:"'java-1.8.0-openjdk' package(s) on Mageia 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk", rpm:"java-1.8.0-openjdk~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-accessibility", rpm:"java-1.8.0-openjdk-accessibility~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-demo", rpm:"java-1.8.0-openjdk-demo~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-devel", rpm:"java-1.8.0-openjdk-devel~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-headless", rpm:"java-1.8.0-openjdk-headless~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-javadoc", rpm:"java-1.8.0-openjdk-javadoc~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.8.0-openjdk-src", rpm:"java-1.8.0-openjdk-src~1.8.0.91~1.b14.1.mga5", rls:"MAGEIA5"))) {
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
