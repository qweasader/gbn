# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845239");
  script_cve_id("CVE-2021-3995", "CVE-2021-3996");
  script_tag(name:"creation_date", value:"2022-02-10 02:00:32 +0000 (Thu, 10 Feb 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 18:13:00 +0000 (Mon, 29 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5279-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5279-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5279-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux' package(s) announced via the USN-5279-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that util-linux incorrectly handled unmounting FUSE
filesystems. A local attacker could possibly use this issue to unmount
FUSE filesystems belonging to other users.");

  script_tag(name:"affected", value:"'util-linux' package(s) on Ubuntu 20.04, Ubuntu 21.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mount", ver:"2.34-0.1ubuntu9.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"util-linux", ver:"2.34-0.1ubuntu9.3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mount", ver:"2.36.1-8ubuntu2.2", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"util-linux", ver:"2.36.1-8ubuntu2.2", rls:"UBUNTU21.10"))) {
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
