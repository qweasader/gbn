# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841789");
  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474");
  script_tag(name:"creation_date", value:"2014-05-02 04:40:58 +0000 (Fri, 02 May 2014)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2169-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|12\.10|13\.10|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2169-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2169-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1311433");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-2169-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2169-1 fixed vulnerabilities in Django. The upstream security patch
for CVE-2014-0472 introduced a regression for certain applications. This
update fixes the problem.

Original advisory details:

 Benjamin Bach discovered that Django incorrectly handled dotted Python
 paths when using the reverse() function. An attacker could use this issue
 to cause Django to import arbitrary modules from the Python path, resulting
 in possible code execution. (CVE-2014-0472)

 Paul McMillan discovered that Django incorrectly cached certain pages that
 contained CSRF cookies. An attacker could possibly use this flaw to obtain
 a valid cookie and perform attacks which bypass the CSRF restrictions.
 (CVE-2014-0473)

 Michael Koziarski discovered that Django did not always perform explicit
 conversion of certain fields when using a MySQL database. An attacker
 could possibly use this issue to obtain unexpected results. (CVE-2014-0474)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10, Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.1.1-2ubuntu1.11", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.3.1-4ubuntu1.10", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.4.1-2ubuntu0.6", rls:"UBUNTU12.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.5.4-1ubuntu1.2", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.6.1-2ubuntu0.2", rls:"UBUNTU14.04 LTS"))) {
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
