# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.66.1");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-66-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-66-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-66-1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/384920");
  script_xref(name:"URL", value:"http://www.securitytracker.com/alerts/2004/Oct/1011984.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php4' package(s) announced via the USN-66-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FraMe from kernelpanik.org reported that the cURL module does not
respect open_basedir restrictions. As a result, scripts which used
cURL to open files with an user-specified path could read arbitrary
local files outside of the open_basedir directory.

Stefano Di Paola discovered a vulnerability in PHP's shmop_write()
function. Its 'offset' parameter was not checked for negative values,
which allowed an attacker to write arbitrary data to arbitrary memory
locations. A script which passed unchecked parameters to
shmop_write() could possibly be exploited to execute arbitrary code
with the privileges of the web server and to bypass safe mode
restrictions.");

  script_tag(name:"affected", value:"'php4' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php4", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-cgi", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-curl", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-dev", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-domxml", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-gd", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-ldap", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mcal", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mhash", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-mysql", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-odbc", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-pear", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-recode", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-snmp", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-sybase", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php4-xslt", ver:"4.3.8-3ubuntu7.3", rls:"UBUNTU4.10"))) {
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
