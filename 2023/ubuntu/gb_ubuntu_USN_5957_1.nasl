# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5957.1");
  script_cve_id("CVE-2018-19105", "CVE-2021-21898", "CVE-2021-21899", "CVE-2021-21900", "CVE-2021-45341", "CVE-2021-45342", "CVE-2021-45343");
  script_tag(name:"creation_date", value:"2023-03-16 04:11:27 +0000 (Thu, 16 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 14:54:25 +0000 (Mon, 31 Jan 2022)");

  script_name("Ubuntu: Security Advisory (USN-5957-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5957-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5957-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'librecad' package(s) announced via the USN-5957-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cody Sixteen discovered that LibreCAD incorrectly
handled memory when parsing DXF files. An attacker could
use this issue to cause LibreCAD to crash, leading to a
denial of service. This issue only affected
Ubuntu 16.04 ESM and Ubuntu 18.04 ESM. (CVE-2018-19105)

Lilith of Cisco Talos discovered that LibreCAD incorrectly
handled memory when parsing DWG files. An attacker could
use this issue to cause LibreCAD to crash, leading to a
denial of service, or possibly execute arbitrary code.
(CVE-2021-21898, CVE-2021-21899)

Lilith of Cisco Talos discovered that LibreCAD incorrectly
handled memory when parsing DRW files. An attacker could
use this issue to cause LibreCAD to crash, leading to a
denial of service, or possibly execute arbitrary code.
(CVE-2021-21900)

Albin Eldstal-Ahrens discovered that LibreCAD incorrectly
handled memory when parsing JWW files. An attacker could
use this issue to cause LibreCAD to crash, leading to a
denial of service, or possibly execute arbitrary code.
(CVE-2021-45341, CVE-2021-45342)

Albin Eldstal-Ahrens discovered that LibreCAD incorrectly
handled memory when parsing DXF files. An attacker could
use this issue to cause LibreCAD to crash, leading to a
denial of service. (CVE-2021-45343)");

  script_tag(name:"affected", value:"'librecad' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"librecad", ver:"2.0.9-2ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"librecad", ver:"2.1.2-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"librecad", ver:"2.1.3-1.2+deb10u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
