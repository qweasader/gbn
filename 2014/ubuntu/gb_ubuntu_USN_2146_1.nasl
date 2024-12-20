# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841754");
  script_cve_id("CVE-2014-0106");
  script_tag(name:"creation_date", value:"2014-03-17 08:16:26 +0000 (Mon, 17 Mar 2014)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2146-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2146-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1223297");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the USN-2146-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sebastien Macke discovered that Sudo incorrectly filtered environment
variables when the env_reset option was disabled. A local attacker could
use this issue to possibly run unintended commands by using environment
variables that were intended to be blocked. In a default Ubuntu
installation, the env_reset option is enabled by default. This issue only
affected Ubuntu 10.04 LTS and Ubuntu 12.04 LTS. (CVE-2014-0106)

It was discovered that the Sudo init script set a date in the past on
existing timestamp files instead of using epoch to invalidate them
completely. A local attacker could possibly modify the system time to
attempt to reuse timestamp files. This issue only applied to Ubuntu
12.04 LTS, Ubuntu 12.10 and Ubuntu 13.10. (LP: #1223297)");

  script_tag(name:"affected", value:"'sudo' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.7.2p1-1ubuntu5.7", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.7.2p1-1ubuntu5.7", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.3p1-1ubuntu3.6", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.3p1-1ubuntu3.6", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.5p2-1ubuntu1.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.5p2-1ubuntu1.2", rls:"UBUNTU12.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"sudo", ver:"1.8.6p3-0ubuntu3.1", rls:"UBUNTU13.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sudo-ldap", ver:"1.8.6p3-0ubuntu3.1", rls:"UBUNTU13.10"))) {
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
