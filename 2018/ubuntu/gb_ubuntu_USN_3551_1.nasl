# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843437");
  script_cve_id("CVE-2017-13884", "CVE-2017-13885", "CVE-2017-7153", "CVE-2017-7160", "CVE-2017-7161", "CVE-2017-7165", "CVE-2018-4088", "CVE-2018-4096");
  script_tag(name:"creation_date", value:"2018-01-31 06:54:47 +0000 (Wed, 31 Jan 2018)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-27 17:48:00 +0000 (Fri, 27 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3551-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3551-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk' package(s) announced via the USN-3551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the WebKitGTK+ Web and
JavaScript engines. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause a
denial of service, spoof the user interface, or execute arbitrary code.
(CVE-2018-4088, CVE-2018-4096, CVE-2017-7153, CVE-2017-7160,
CVE-2017-7161, CVE-2017-7165, CVE-2017-13884, CVE-2017-13885)");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Ubuntu 16.04, Ubuntu 17.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.18.6-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.18.6-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU17.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.18.6-0ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.18.6-0ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
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
