# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5671.1");
  script_cve_id("CVE-2019-8379", "CVE-2019-8383");
  script_tag(name:"creation_date", value:"2022-10-13 04:42:45 +0000 (Thu, 13 Oct 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-20 15:53:35 +0000 (Wed, 20 Feb 2019)");

  script_name("Ubuntu: Security Advisory (USN-5671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5671-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5671-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'advancecomp' package(s) announced via the USN-5671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that AdvanceCOMP did not properly manage memory of function
be_uint32_read() under certain circumstances. If a user were tricked into
opening a specially crafted binary file, a remote attacker could possibly use
this issue to cause AdvanceCOMP to crash, resulting in a denial of service.
(CVE-2019-8379)

It was discovered that AdvanceCOMP did not properly manage memory of function
adv_png_unfilter_8() under certain circumstances. If a user were tricked into
opening a specially crafted PNG file, a remote attacker could possibly use this
issue to cause AdvanceCOMP to crash, resulting in a denial of service.
(CVE-2019-8383)");

  script_tag(name:"affected", value:"'advancecomp' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"advancecomp", ver:"1.20-1ubuntu0.2+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"advancecomp", ver:"2.1-1ubuntu0.18.04.2", rls:"UBUNTU18.04 LTS"))) {
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
