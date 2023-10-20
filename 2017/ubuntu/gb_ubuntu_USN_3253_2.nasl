# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843202");
  script_cve_id("CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566");
  script_tag(name:"creation_date", value:"2017-06-08 04:04:35 +0000 (Thu, 08 Jun 2017)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-25 11:29:00 +0000 (Tue, 25 Dec 2018)");

  script_name("Ubuntu: Security Advisory (USN-3253-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3253-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3253-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1690380");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nagios3' package(s) announced via the USN-3253-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3253-1 fixed vulnerabilities in Nagios. The update prevented log files
from being displayed in the web interface. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Nagios incorrectly handled certain long strings. A
 remote authenticated attacker could use this issue to cause Nagios to
 crash, resulting in a denial of service, or possibly obtain sensitive
 information. (CVE-2013-7108, CVE-2013-7205)

 It was discovered that Nagios incorrectly handled certain long messages to
 cmd.cgi. A remote attacker could possibly use this issue to cause Nagios to
 crash, resulting in a denial of service. (CVE-2014-1878)

 Dawid Golunski discovered that Nagios incorrectly handled symlinks when
 accessing log files. A local attacker could possibly use this issue to
 elevate privileges. In the default installation of Ubuntu, this should be
 prevented by the Yama link restrictions. (CVE-2016-9566)");

  script_tag(name:"affected", value:"'nagios3' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-cgi", ver:"3.5.1-1ubuntu1.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-core", ver:"3.5.1-1ubuntu1.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-cgi", ver:"3.5.1.dfsg-2.1ubuntu1.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-core", ver:"3.5.1.dfsg-2.1ubuntu1.3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-cgi", ver:"3.5.1.dfsg-2.1ubuntu3.3", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-core", ver:"3.5.1.dfsg-2.1ubuntu3.3", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-cgi", ver:"3.5.1.dfsg-2.1ubuntu5.2", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nagios3-core", ver:"3.5.1.dfsg-2.1ubuntu5.2", rls:"UBUNTU17.04"))) {
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
