# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845280");
  script_cve_id("CVE-2021-25636");
  script_tag(name:"creation_date", value:"2022-03-16 02:00:23 +0000 (Wed, 16 Mar 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 19:15:00 +0000 (Thu, 03 Mar 2022)");

  script_name("Ubuntu: Security Advisory (USN-5330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5330-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5330-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the USN-5330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LibreOffice incorrectly handled digital signatures.
An attacker could possibly use this issue to create a specially crafted
document that would display a validly signed indicator, contrary to
expectations.");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:6.0.7-0ubuntu0.18.04.11", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:6.4.7-0ubuntu0.20.04.4", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice-core", ver:"1:7.2.5-0ubuntu0.21.10.3", rls:"UBUNTU21.10"))) {
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
