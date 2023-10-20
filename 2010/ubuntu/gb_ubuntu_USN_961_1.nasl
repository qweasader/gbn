# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840459");
  script_cve_id("CVE-2009-4270", "CVE-2009-4897", "CVE-2010-1628", "CVE-2010-1869");
  script_tag(name:"creation_date", value:"2010-07-16 08:40:49 +0000 (Fri, 16 Jul 2010)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-961-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|8\.04\ LTS|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-961-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-961-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-961-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Srbecky discovered that Ghostscript incorrectly handled debug
logging. If a user or automated system were tricked into opening a crafted
PDF file, an attacker could cause a denial of service or execute arbitrary
code with privileges of the user invoking the program. This issue only
affected Ubuntu 9.04 and Ubuntu 9.10. The default compiler options for
affected releases should reduce the vulnerability to a denial of service.
(CVE-2009-4270)

It was discovered that Ghostscript incorrectly handled certain malformed
files. If a user or automated system were tricked into opening a crafted
Postscript or PDF file, an attacker could cause a denial of service or
execute arbitrary code with privileges of the user invoking the program.
This issue only affected Ubuntu 8.04 LTS and Ubuntu 9.04. (CVE-2009-4897)

Dan Rosenberg discovered that Ghostscript incorrectly handled certain
recursive Postscript files. If a user or automated system were tricked into
opening a crafted Postscript file, an attacker could cause a denial of
service or execute arbitrary code with privileges of the user invoking the
program. (CVE-2010-1628)

Rodrigo Rubira Branco and Dan Rosenberg discovered that Ghostscript
incorrectly handled certain malformed Postscript files. If a user or
automated system were tricked into opening a crafted Postscript file, an
attacker could cause a denial of service or execute arbitrary code with
privileges of the user invoking the program. This issue only affected
Ubuntu 8.04 LTS, 9.04 and 9.10. (CVE-2010-1869)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.71.dfsg.1-0ubuntu5.2", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.61.dfsg.1-1ubuntu3.3", rls:"UBUNTU8.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.64.dfsg.1-0ubuntu8.1", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libgs8", ver:"8.70.dfsg.1-0ubuntu3.1", rls:"UBUNTU9.10"))) {
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
