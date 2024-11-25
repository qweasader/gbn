# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6690.1");
  script_cve_id("CVE-2023-3966", "CVE-2023-5366");
  script_tag(name:"creation_date", value:"2024-03-13 04:08:51 +0000 (Wed, 13 Mar 2024)");
  script_version("2024-03-13T05:05:57+0000");
  script_tag(name:"last_modification", value:"2024-03-13 05:05:57 +0000 (Wed, 13 Mar 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 17:40:07 +0000 (Thu, 12 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-6690-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6690-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6690-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openvswitch' package(s) announced via the USN-6690-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Timothy Redaelli and Haresh Khandelwal discovered that Open vSwitch
incorrectly handled certain crafted Geneve packets when hardware offloading
via the netlink path is enabled. A remote attacker could possibly use this
issue to cause Open vSwitch to crash, leading to a denial of service.
(CVE-2023-3966)

It was discovered that Open vSwitch incorrectly handled certain ICMPv6
Neighbor Advertisement packets. A remote attacker could possibly use this
issue to redirect traffic to arbitrary IP addresses. (CVE-2023-5366)");

  script_tag(name:"affected", value:"'openvswitch' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.13.8-0ubuntu1.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-openvswitch", ver:"2.13.8-0ubuntu1.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"2.17.9-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-openvswitch", ver:"2.17.9-0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"openvswitch-common", ver:"3.2.2-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-openvswitch", ver:"3.2.2-0ubuntu0.23.10.1", rls:"UBUNTU23.10"))) {
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
