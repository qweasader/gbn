# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843147");
  script_cve_id("CVE-2016-10217", "CVE-2016-10219", "CVE-2016-10220", "CVE-2017-5951", "CVE-2017-7207", "CVE-2017-8291");
  script_tag(name:"creation_date", value:"2017-04-29 05:16:15 +0000 (Sat, 29 Apr 2017)");
  script_version("2024-08-08T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-08-08 05:05:41 +0000 (Thu, 08 Aug 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-02 13:01:53 +0000 (Tue, 02 Jul 2024)");

  script_name("Ubuntu: Security Advisory (USN-3272-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|16\.04\ LTS|16\.10|17\.04)");

  script_xref(name:"Advisory-ID", value:"USN-3272-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3272-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the USN-3272-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ghostscript improperly handled parameters to
the rsdparams and eqproc commands. An attacker could use these to
craft a malicious document that could disable -dSAFER protections,
thereby allowing the execution of arbitrary code, or cause a denial
of service (application crash). (CVE-2017-8291)

Kamil Frankowicz discovered a use-after-free vulnerability in the
color management module of Ghostscript. An attacker could use this
to cause a denial of service (application crash). (CVE-2016-10217)

Kamil Frankowicz discovered a divide-by-zero error in the scan
conversion code in Ghostscript. An attacker could use this to cause
a denial of service (application crash). (CVE-2016-10219)

Kamil Frankowicz discovered multiple NULL pointer dereference errors in
Ghostscript. An attacker could use these to cause a denial of service
(application crash). (CVE-2016-10220, CVE-2017-5951, CVE-2017-7207)");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.05~dfsg-0ubuntu4.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.05~dfsg-0ubuntu4.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.05~dfsg-0ubuntu4.5", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.05~dfsg-0ubuntu4.5", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.10~dfsg-0ubuntu10.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.10~dfsg-0ubuntu10.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.10~dfsg-0ubuntu10.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.10~dfsg-0ubuntu10.7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.18~dfsg~0-0ubuntu2.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.18~dfsg~0-0ubuntu2.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.18~dfsg~0-0ubuntu2.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.18~dfsg~0-0ubuntu2.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.10") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.19~dfsg+1-0ubuntu6.4", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.19~dfsg+1-0ubuntu6.4", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.19~dfsg+1-0ubuntu6.4", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.19~dfsg+1-0ubuntu6.4", rls:"UBUNTU16.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.04") {

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript", ver:"9.19~dfsg+1-0ubuntu7.2", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ghostscript-x", ver:"9.19~dfsg+1-0ubuntu7.2", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9", ver:"9.19~dfsg+1-0ubuntu7.2", rls:"UBUNTU17.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgs9-common", ver:"9.19~dfsg+1-0ubuntu7.2", rls:"UBUNTU17.04"))) {
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
