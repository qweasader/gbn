# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6234.1");
  script_cve_id("CVE-2023-35788");
  script_tag(name:"creation_date", value:"2023-07-19 04:14:28 +0000 (Wed, 19 Jul 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:19 +0000 (Fri, 23 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6234-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6234-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6234-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023220");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023577");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-xilinx-zynqmp' package(s) announced via the USN-6234-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hangyu Hua discovered that the Flower classifier implementation in the
Linux kernel contained an out-of-bounds write vulnerability. An attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2023-35788, LP: #2023577)

It was discovered that for some Intel processors the INVLPG instruction
implementation did not properly flush global TLB entries when PCIDs are
enabled. An attacker could use this to expose sensitive information
(kernel memory) or possibly cause undesired behaviors. (LP: #2023220)");

  script_tag(name:"affected", value:"'linux-xilinx-zynqmp' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1025-xilinx-zynqmp", ver:"5.4.0-1025.29", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"5.4.0.1025.27", rls:"UBUNTU20.04 LTS"))) {
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
