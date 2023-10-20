# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841157");
  script_cve_id("CVE-2012-3955");
  script_tag(name:"creation_date", value:"2012-09-22 06:29:42 +0000 (Sat, 22 Sep 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-1571-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1571-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1571-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1016643");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dhcp3, isc-dhcp' package(s) announced via the USN-1571-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Glen Eustace discovered that the DHCP server incorrectly handled IPv6
expiration times. A remote attacker could use this issue to cause DHCP to
crash, resulting in a denial of service. This issue only affected Ubuntu
11.04, Ubuntu 11.10 and Ubuntu 12.04 LTS. (CVE-2012-3955)

Dan Rosenberg discovered that the DHCP AppArmor profile could be escaped by
using environment variables. This update mitigates the issue by sanitizing
certain variables in the DHCP shell scripts.");

  script_tag(name:"affected", value:"'dhcp3, isc-dhcp' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10, Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-client", ver:"3.1.3-2ubuntu3.4", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dhcp3-server", ver:"3.1.3-2ubuntu3.4", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.1.1-P1-15ubuntu9.6", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.1.1-P1-15ubuntu9.6", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.1.1-P1-17ubuntu10.5", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.1.1-P1-17ubuntu10.5", rls:"UBUNTU11.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-client", ver:"4.1.ESV-R4-0ubuntu5.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isc-dhcp-server", ver:"4.1.ESV-R4-0ubuntu5.5", rls:"UBUNTU12.04 LTS"))) {
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
