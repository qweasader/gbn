# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64321");
  script_cve_id("CVE-2009-1171");
  script_tag(name:"creation_date", value:"2009-06-29 22:29:55 +0000 (Mon, 29 Jun 2009)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-791-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU9\.04");

  script_xref(name:"Advisory-ID", value:"USN-791-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-791-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'moodle' package(s) announced via the USN-791-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian Eibl discovered that the TeX filter in Moodle allowed any
function to be used. An authenticated remote attacker could post
a specially crafted TeX formula to execute arbitrary TeX functions,
potentially reading any file accessible to the web server user, leading
to a loss of privacy. (CVE-2009-1171, MSA-09-0009)");

  script_tag(name:"affected", value:"'moodle' package(s) on Ubuntu 9.04.");

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

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.9.4.dfsg-0ubuntu1.1", rls:"UBUNTU9.04"))) {
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
