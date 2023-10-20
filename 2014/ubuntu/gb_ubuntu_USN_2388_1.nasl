# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842012");
  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6513", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6527", "CVE-2014-6531", "CVE-2014-6558");
  script_tag(name:"creation_date", value:"2014-10-23 04:00:23 +0000 (Thu, 23 Oct 2014)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-2388-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2388-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1382205");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-7' package(s) announced via the USN-2388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was discovered in the OpenJDK JRE related to information
disclosure and data integrity. An attacker could exploit this to expose
sensitive data over the network. (CVE-2014-6457)

Several vulnerabilities were discovered in the OpenJDK JRE related to data
integrity. (CVE-2014-6502, CVE-2014-6512, CVE-2014-6519, CVE-2014-6527,
CVE-2014-6558)

Several vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure. An attacker could exploit these to expose sensitive
data over the network. (CVE-2014-6504, CVE-2014-6511, CVE-2014-6517,
CVE-2014-6531)

Two vulnerabilities were discovered in the OpenJDK JRE related to
information disclosure, data integrity and availability. An attacker could
exploit these to cause a denial of service or expose sensitive data over
the network. (CVE-2014-6506, CVE-2014-6513)");

  script_tag(name:"affected", value:"'openjdk-7' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-7-jre-jamvm", ver:"7u71-2.5.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre", ver:"7u71-2.5.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-headless", ver:"7u71-2.5.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-lib", ver:"7u71-2.5.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-7-jre-zero", ver:"7u71-2.5.3-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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
