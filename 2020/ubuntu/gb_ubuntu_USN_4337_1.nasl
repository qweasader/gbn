# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844402");
  script_cve_id("CVE-2020-2754", "CVE-2020-2755", "CVE-2020-2756", "CVE-2020-2757", "CVE-2020-2767", "CVE-2020-2773", "CVE-2020-2778", "CVE-2020-2781", "CVE-2020-2800", "CVE-2020-2803", "CVE-2020-2805", "CVE-2020-2816", "CVE-2020-2830");
  script_tag(name:"creation_date", value:"2020-04-23 03:01:03 +0000 (Thu, 23 Apr 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-17 16:52:45 +0000 (Fri, 17 Apr 2020)");

  script_name("Ubuntu: Security Advisory (USN-4337-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|19\.10)");

  script_xref(name:"Advisory-ID", value:"USN-4337-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4337-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-8, openjdk-lts' package(s) announced via the USN-4337-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenJDK incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause a denial of
service while processing a specially crafted regular expression.
(CVE-2020-2754, CVE-2020-2755)

It was discovered that OpenJDK incorrectly handled class descriptors and
catching exceptions during object stream deserialization. An attacker could
possibly use this issue to cause a denial of service while processing a
specially crafted serialized input. (CVE-2020-2756, CVE-2020-2757)

Bengt Jonsson, Juraj Somorovsky, Kostis Sagonas, Paul Fiterau Brostean and
Robert Merget discovered that OpenJDK incorrectly handled certificate messages
during TLS handshake. An attacker could possibly use this issue to bypass
certificate verification and insert, edit or obtain sensitive information. This
issue only affected OpenJDK 11. (CVE-2020-2767)

It was discovered that OpenJDK incorrectly handled exceptions thrown by
unmarshalKeyInfo() and unmarshalXMLSignature(). An attacker could possibly use
this issue to cause a denial of service while reading key info or XML signature
data from XML input. (CVE-2020-2773)

Peter Dettman discovered that OpenJDK incorrectly handled SSLParameters in
setAlgorithmConstraints(). An attacker could possibly use this issue to
override the defined systems security policy and lead to the use of weak
crypto algorithms that should be disabled. This issue only affected
OpenJDK 11. (CVE-2020-2778)

Simone Bordet discovered that OpenJDK incorrectly re-used single null TLS
sessions for new TLS connections. A remote attacker could possibly use this
issue to cause a denial of service. (CVE-2020-2781)

Dan Amodio discovered that OpenJDK did not restrict the use of CR and LF
characters in values for HTTP headers. An attacker could possibly use this
issue to insert, edit or obtain sensitive information. (CVE-2020-2800)

Nils Emmerich discovered that OpenJDK incorrectly checked boundaries or
argument types. An attacker could possibly use this issue to bypass sandbox
restrictions causing unspecified impact. (CVE-2020-2803, CVE-2020-2805)

It was discovered that OpenJDK incorrectly handled application data packets
during TLS handshake. An attacker could possibly use this issue to insert,
edit or obtain sensitive information. This issue only affected OpenJDK 11.
(CVE-2020-2816)

It was discovered that OpenJDK incorrectly handled certain regular
expressions. An attacker could possibly use this issue to cause a denial of
service. (CVE-2020-2830)");

  script_tag(name:"affected", value:"'openjdk-8, openjdk-lts' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u252-b09-1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u252-b09-1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u252-b09-1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-jamvm", ver:"8u252-b09-1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u252-b09-1~16.04", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.7+10-2ubuntu2~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.7+10-2ubuntu2~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.7+10-2ubuntu2~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.7+10-2ubuntu2~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u252-b09-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u252-b09-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u252-b09-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u252-b09-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jdk", ver:"11.0.7+10-2ubuntu2~19.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre", ver:"11.0.7+10-2ubuntu2~19.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-headless", ver:"11.0.7+10-2ubuntu2~19.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-11-jre-zero", ver:"11.0.7+10-2ubuntu2~19.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jdk", ver:"8u252-b09-1~19.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre", ver:"8u252-b09-1~19.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-headless", ver:"8u252-b09-1~19.10", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-8-jre-zero", ver:"8u252-b09-1~19.10", rls:"UBUNTU19.10"))) {
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
