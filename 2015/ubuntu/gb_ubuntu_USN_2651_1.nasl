# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842253");
  script_cve_id("CVE-2010-4651", "CVE-2014-9637", "CVE-2015-1196", "CVE-2015-1395", "CVE-2015-1396");
  script_tag(name:"creation_date", value:"2015-06-24 04:17:46 +0000 (Wed, 24 Jun 2015)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-17 18:15:00 +0000 (Mon, 17 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-2651-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2651-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2651-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch' package(s) announced via the USN-2651-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered that GNU patch did not correctly handle file paths in
patch files. An attacker could specially craft a patch file that could
overwrite arbitrary files with the privileges of the user invoking the program.
This issue only affected Ubuntu 12.04 LTS. (CVE-2010-4651)

Laszlo Boszormenyi discovered that GNU patch did not correctly handle some
patch files. An attacker could specially craft a patch file that could cause a
denial of service. (CVE-2014-9637)

Jakub Wilk discovered that GNU patch did not correctly handle symbolic links in
git style patch files. An attacker could specially craft a patch file that
could overwrite arbitrary files with the privileges of the user invoking the
program. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1196)

Jakub Wilk discovered that GNU patch did not correctly handle file renames in
git style patch files. An attacker could specially craft a patch file that
could overwrite arbitrary files with the privileges of the user invoking the
program. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
(CVE-2015-1395)

Jakub Wilk discovered the fix for CVE-2015-1196 was incomplete for GNU patch.
An attacker could specially craft a patch file that could overwrite arbitrary
files with the privileges of the user invoking the program. This issue only
affected Ubuntu 14.04 LTS and Ubuntu 14.10. (CVE-2015-1396)");

  script_tag(name:"affected", value:"'patch' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"patch", ver:"2.6.1-3ubuntu0.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"patch", ver:"2.7.1-4ubuntu2.3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"patch", ver:"2.7.1-5ubuntu0.3", rls:"UBUNTU14.10"))) {
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
