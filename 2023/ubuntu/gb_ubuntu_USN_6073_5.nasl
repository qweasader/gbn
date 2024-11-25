# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6073.5");
  script_tag(name:"creation_date", value:"2023-05-15 04:11:49 +0000 (Mon, 15 May 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6073-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6073-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6073-5");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2019460");
  script_xref(name:"URL", value:"https://security.openstack.org/ossa/OSSA-2023-003.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nova' package(s) announced via the USN-6073-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6073-3 fixed a vulnerability in Nova. The update introduced a
regression causing Nova to be unable to detach volumes from instances. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Jan Wasilewski and Gorka Eguileor discovered that Nova incorrectly
 handled deleted volume attachments. An authenticated user or attacker could
 possibly use this issue to gain access to sensitive information.

 This update may require configuration changes to be completely effective,
 please see the upstream advisory for more information:

 [link moved to references]");

  script_tag(name:"affected", value:"'nova' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-nova", ver:"2:21.2.4-0ubuntu2.4", rls:"UBUNTU20.04 LTS"))) {
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
