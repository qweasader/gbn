# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843447");
  script_cve_id("CVE-2018-5089", "CVE-2018-5090", "CVE-2018-5091", "CVE-2018-5092", "CVE-2018-5093", "CVE-2018-5094", "CVE-2018-5095", "CVE-2018-5097", "CVE-2018-5098", "CVE-2018-5099", "CVE-2018-5100", "CVE-2018-5101", "CVE-2018-5102", "CVE-2018-5103", "CVE-2018-5104", "CVE-2018-5105", "CVE-2018-5106", "CVE-2018-5107", "CVE-2018-5108", "CVE-2018-5109", "CVE-2018-5111", "CVE-2018-5112", "CVE-2018-5113", "CVE-2018-5114", "CVE-2018-5115", "CVE-2018-5116", "CVE-2018-5117", "CVE-2018-5122");
  script_tag(name:"creation_date", value:"2018-02-14 07:39:47 +0000 (Wed, 14 Feb 2018)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-3544-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|17\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3544-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3544-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1749025");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3544-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3544-1 fixed vulnerabilities in Firefox. The update caused a web
compatibility regression and a tab crash during printing in some
circumstances. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service via application
 crash, spoof the origin in audio capture prompts, trick the user in to
 providing HTTP credentials for another origin, spoof the addressbar
 contents, or execute arbitrary code. (CVE-2018-5089, CVE-2018-5090,
 CVE-2018-5091, CVE-2018-5092, CVE-2018-5093, CVE-2018-5094, CVE-2018-5095,
 CVE-2018-5097, CVE-2018-5098, CVE-2018-5099, CVE-2018-5100, CVE-2018-5101,
 CVE-2018-5102, CVE-2018-5103, CVE-2018-5104, CVE-2018-5109, CVE-2018-5114,
 CVE-2018-5115, CVE-2018-5117, CVE-2018-5122)

 Multiple security issues were discovered in WebExtensions. If a user were
 tricked in to installing a specially crafted extension, an attacker could
 potentially exploit these to gain additional privileges, bypass
 same-origin restrictions, or execute arbitrary code. (CVE-2018-5105,
 CVE-2018-5113, CVE-2018-5116)

 A security issue was discovered with the developer tools. If a user were
 tricked in to opening a specially crafted website with the developer tools
 open, an attacker could potentially exploit this to obtain sensitive
 information from other origins. (CVE-2018-5106)

 A security issue was discovered with printing. An attacker could
 potentially exploit this to obtain sensitive information from local files.
 (CVE-2018-5107)

 It was discovered that manually entered blob URLs could be accessed by
 subsequent private browsing tabs. If a user were tricked in to entering
 a blob URL, an attacker could potentially exploit this to obtain sensitive
 information from a private browsing context. (CVE-2018-5108)

 It was discovered that dragging certain specially formatted URLs to the
 addressbar could cause the wrong URL to be displayed. If a user were
 tricked in to opening a specially crafted website and dragging a URL to
 the addressbar, an attacker could potentially exploit this to spoof the
 addressbar contents. (CVE-2018-5111)

 It was discovered that WebExtension developer tools panels could open
 non-relative URLs. If a user were tricked in to installing a specially
 crafted extension and running the developer tools, an attacker could
 potentially exploit this to gain additional privileges. (CVE-2018-5112)

 It was discovered that ActivityStream images can attempt to load local
 content through file: URLs. If a user were tricked in to opening a
 specially crafted website, an attacker could potentially exploit this in
 combination with another vulnerability that allowed sandbox protections to
 be bypassed, in order to obtain sensitive ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"58.0.2+build1-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"58.0.2+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"58.0.2+build1-0ubuntu0.17.10.1", rls:"UBUNTU17.10"))) {
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
