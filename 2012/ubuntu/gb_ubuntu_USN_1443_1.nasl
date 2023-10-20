# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841009");
  script_cve_id("CVE-2012-0948", "CVE-2012-0949");
  script_tag(name:"creation_date", value:"2012-05-22 04:40:48 +0000 (Tue, 22 May 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1443-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1443-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1443-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'update-manager' package(s) announced via the USN-1443-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Update Manager created system state archive files
with incorrect permissions when upgrading releases. A local user could
possibly use this to read repository credentials. (CVE-2012-0948)

Felix Geyer discovered that the Update Manager Apport hook incorrectly
uploaded certain system state archive files to Launchpad when reporting
bugs. This could possibly result in repository credentials being included
in public bug reports. (CVE-2012-0949)");

  script_tag(name:"affected", value:"'update-manager' package(s) on Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.150.5.3", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.152.25.11", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"update-manager-core", ver:"1:0.156.14.4", rls:"UBUNTU12.04 LTS"))) {
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
