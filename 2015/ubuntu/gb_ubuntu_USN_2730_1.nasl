# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842427");
  script_cve_id("CVE-2012-4428", "CVE-2015-5177");
  script_tag(name:"creation_date", value:"2015-09-04 06:15:21 +0000 (Fri, 04 Sep 2015)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-07 13:01:00 +0000 (Tue, 07 Nov 2017)");

  script_name("Ubuntu: Security Advisory (USN-2730-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2730-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2730-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openslp-dfsg' package(s) announced via the USN-2730-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Georgi Geshev discovered that OpenSLP incorrectly handled processing
certain service requests. A remote attacker could possibly use this issue
to cause OpenSLP to crash, resulting in a denial of service. This issue
only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2012-4428)

Qinghao Tang discovered that OpenSLP incorrectly handled processing certain
messages. A remote attacker could possibly use this issue to cause
OpenSLP to crash, resulting in a denial of service. (CVE-2015-5177)");

  script_tag(name:"affected", value:"'openslp-dfsg' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libslp1", ver:"1.2.1-7.8ubuntu1.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libslp1", ver:"1.2.1-9ubuntu0.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libslp1", ver:"1.2.1-10ubuntu0.1", rls:"UBUNTU15.04"))) {
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
