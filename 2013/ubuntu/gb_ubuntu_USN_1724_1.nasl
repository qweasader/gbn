# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841310");
  script_cve_id("CVE-2012-1541", "CVE-2012-3213", "CVE-2012-3342", "CVE-2013-0351", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0430", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0438", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0444", "CVE-2013-0445", "CVE-2013-0446", "CVE-2013-0448", "CVE-2013-0449", "CVE-2013-0450", "CVE-2013-1473", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1481");
  script_tag(name:"creation_date", value:"2013-02-15 05:52:47 +0000 (Fri, 15 Feb 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1724-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.10|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1724-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1724-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6, openjdk-7' package(s) announced via the USN-1724-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to cause a denial of service. (CVE-2012-1541, CVE-2012-3342, CVE-2013-0351,
CVE-2013-0419, CVE-2013-0423, CVE-2013-0446, CVE-2012-3213, CVE-2013-0425,
CVE-2013-0426, CVE-2013-0428, CVE-2013-0429, CVE-2013-0430, CVE-2013-0441,
CVE-2013-0442, CVE-2013-0445, CVE-2013-0450, CVE-2013-1475, CVE-2013-1476,
CVE-2013-1478, CVE-2013-1480)

Vulnerabilities were discovered in the OpenJDK JRE related to information
disclosure. (CVE-2013-0409, CVE-2013-0434, CVE-2013-0438)

Several data integrity vulnerabilities were discovered in the OpenJDK JRE.
(CVE-2013-0424, CVE-2013-0427, CVE-2013-0433, CVE-2013-1473)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. (CVE-2013-0432, CVE-2013-0435,
CVE-2013-0443)

A vulnerability was discovered in the OpenJDK JRE related to availability.
An attacker could exploit this to cause a denial of service.
(CVE-2013-0440)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and data integrity. An attacker could exploit this to cause a
denial of service. This issue only affected Ubuntu 12.10. (CVE-2013-0444)

A data integrity vulnerability was discovered in the OpenJDK JRE. This
issue only affected Ubuntu 12.10. (CVE-2013-0448)

An information disclosure vulnerability was discovered in the OpenJDK JRE.
This issue only affected Ubuntu 12.10. (CVE-2013-0449)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and data integrity. An attacker could exploit this to cause a
denial of service. This issue did not affect Ubuntu 12.10. (CVE-2013-1481)");

  script_tag(name:"affected", value:"'openjdk-6, openjdk-7' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.1-2ubuntu0.10.04.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.1-2ubuntu0.11.10.2", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-jamvm", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b27-1.12.1-2ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u13-2.3.6-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
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
