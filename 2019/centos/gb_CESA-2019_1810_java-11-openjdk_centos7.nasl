# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883087");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2818", "CVE-2019-2821");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-06 18:47:00 +0000 (Thu, 06 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-07-25 02:01:07 +0000 (Thu, 25 Jul 2019)");
  script_name("CentOS Update for java-11-openjdk CESA-2019:1810 centos7");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2019:1810");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2019-July/023371.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the CESA-2019:1810 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The java-11-openjdk packages provide the OpenJDK 11 Java Runtime
Environment and the OpenJDK 11 Java Software Development Kit.

Security Fix(es):

  * OpenJDK: Side-channel attack risks in Elliptic Curve (EC) cryptography
(Security, 8208698) (CVE-2019-2745)

  * OpenJDK: Insufficient checks of suppressed exceptions in deserialization
(Utilities, 8212328) (CVE-2019-2762)

  * OpenJDK: Unbounded memory allocation during deserialization in
Collections (Utilities, 8213432) (CVE-2019-2769)

  * OpenJDK: Missing URL format validation (Networking, 8221518)
(CVE-2019-2816)

  * OpenJDK: Incorrect handling of certificate status messages during TLS
handshake (JSSE, 8222678) (CVE-2019-2821)

  * OpenJDK: Insufficient restriction of privileges in AccessController
(Security, 8216381) (CVE-2019-2786)

  * OpenJDK: Non-constant time comparison in ChaCha20Cipher (Security,
8221344) (CVE-2019-2818)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'java-11-openjdk' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debug", rpm:"java-11-openjdk-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo-debug", rpm:"java-11-openjdk-demo-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel-debug", rpm:"java-11-openjdk-devel-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless-debug", rpm:"java-11-openjdk-headless-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc-debug", rpm:"java-11-openjdk-javadoc-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc-zip", rpm:"java-11-openjdk-javadoc-zip~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc-zip-debug", rpm:"java-11-openjdk-javadoc-zip-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods-debug", rpm:"java-11-openjdk-jmods-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src-debug", rpm:"java-11-openjdk-src-debug~11.0.4.11~0.el7_6", rls:"CentOS7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
