# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7082.1");
  script_cve_id("CVE-2024-41311");
  script_tag(name:"creation_date", value:"2024-10-23 12:20:39 +0000 (Wed, 23 Oct 2024)");
  script_version("2024-10-24T05:05:32+0000");
  script_tag(name:"last_modification", value:"2024-10-24 05:05:32 +0000 (Thu, 24 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7082-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7082-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7082-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libheif' package(s) announced via the USN-7082-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gerrard Tai discovered that libheif did not properly validate certain
images, leading to out-of-bounds read and write vulnerability. If a user
or automated system were tricked into opening a specially crafted file, an
attacker could possibly use this issue to cause a denial of service or to
obtain sensitive information.");

  script_tag(name:"affected", value:"'libheif' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libheif1", ver:"1.17.6-1ubuntu4.1", rls:"UBUNTU24.04 LTS"))) {
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
