# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841074");
  script_cve_id("CVE-2012-3360", "CVE-2012-3361");
  script_tag(name:"creation_date", value:"2012-07-06 04:29:13 +0000 (Fri, 06 Jul 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1497-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1497-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1497-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova' package(s) announced via the USN-1497-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matthias Weckbecker discovered that, when using the OpenStack API to
setup libvirt-based hypervisors, an authenticated user could inject
files in arbitrary locations on the file system of the host running
Nova. A remote attacker could use this to gain root privileges. This
issue only affects Ubuntu 12.04 LTS. (CVE-2012-3360)

Padraig Brady discovered that an authenticated user could corrupt
arbitrary files of the host running Nova. A remote attacker could
use this to cause a denial of service or possibly gain privileges.
(CVE-2012-3361)");

  script_tag(name:"affected", value:"'nova' package(s) on Ubuntu 11.10, Ubuntu 12.04.");

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

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"2011.3-0ubuntu6.9", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-nova", ver:"2012.1+stable~20120612-3ee026e-0ubuntu1.1", rls:"UBUNTU12.04 LTS"))) {
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
