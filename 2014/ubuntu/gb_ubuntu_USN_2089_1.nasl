# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841692");
  script_cve_id("CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5805", "CVE-2013-5806", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851", "CVE-2013-5878", "CVE-2013-5884", "CVE-2013-5893", "CVE-2013-5896", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0376", "CVE-2014-0408", "CVE-2014-0411", "CVE-2014-0416", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0428");
  script_tag(name:"creation_date", value:"2014-01-27 05:52:30 +0000 (Mon, 27 Jan 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2089-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.10|13\.04|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2089-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2089-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2089-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure and data integrity. An attacker could exploit these
to expose sensitive data over the network. (CVE-2013-3829, CVE-2013-5783,
CVE-2013-5804, CVE-2014-0411)

Several vulnerabilities were discovered in the OpenJDK JRE related to
availability. An attacker could exploit these to cause a denial of service.
(CVE-2013-4002, CVE-2013-5803, CVE-2013-5823, CVE-2013-5825, CVE-2013-5896,
CVE-2013-5910)

Several vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2013-5772, CVE-2013-5774, CVE-2013-5784, CVE-2013-5797,
CVE-2013-5820, CVE-2014-0376, CVE-2014-0416)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2013-5778, CVE-2013-5780, CVE-2013-5790,
CVE-2013-5800, CVE-2013-5840, CVE-2013-5849, CVE-2013-5851, CVE-2013-5884,
CVE-2014-0368)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2013-5782, CVE-2013-5802, CVE-2013-5809, CVE-2013-5829,
CVE-2013-5814, CVE-2013-5817, CVE-2013-5830, CVE-2013-5842, CVE-2013-5850,
CVE-2013-5878, CVE-2013-5893, CVE-2013-5907, CVE-2014-0373, CVE-2014-0408,
CVE-2014-0422, CVE-2014-0428)

A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and availability. An attacker could exploit this to expose
sensitive data over the network or cause a denial of service.
(CVE-2014-0423)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

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

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-cacao", ver:"7u51-2.4.4-0ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u51-2.4.4-0ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u51-2.4.4-0ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u51-2.4.4-0ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u51-2.4.4-0ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u51-2.4.4-0ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u51-2.4.4-0ubuntu0.13.04.2", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u51-2.4.4-0ubuntu0.13.04.2", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u51-2.4.4-0ubuntu0.13.04.2", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u51-2.4.4-0ubuntu0.13.04.2", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u51-2.4.4-0ubuntu0.13.04.2", rls:"UBUNTU13.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u51-2.4.4-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u51-2.4.4-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u51-2.4.4-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u51-2.4.4-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u51-2.4.4-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
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
