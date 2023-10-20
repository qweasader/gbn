# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842634");
  script_cve_id("CVE-2016-1930", "CVE-2016-1931", "CVE-2016-1933", "CVE-2016-1935", "CVE-2016-1937", "CVE-2016-1938", "CVE-2016-1939", "CVE-2016-1942", "CVE-2016-1944", "CVE-2016-1945", "CVE-2016-1946", "CVE-2016-1947");
  script_tag(name:"creation_date", value:"2016-02-09 05:24:25 +0000 (Tue, 09 Feb 2016)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-2880-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2880-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2880-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1538724");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2880-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2880-1 fixed vulnerabilities in Firefox. This update introduced a
regression which caused Firefox to crash on startup with some configurations.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Bob Clary, Christian Holler, Nils Ohlmeier, Gary Kwong, Jesse Ruderman,
 Carsten Book, Randell Jesup, Nicolas Pierron, Eric Rescorla, Tyson Smith,
 and Gabor Krizsanits discovered multiple memory safety issues in Firefox.
 If a user were tricked in to opening a specially crafted website, an
 attacker could potentially exploit these to cause a denial of service via
 application crash, or execute arbitrary code with the privileges of the
 user invoking Firefox. (CVE-2016-1930, CVE-2016-1931)

 Gustavo Grieco discovered an out-of-memory crash when loading GIF images
 in some circumstances. If a user were tricked in to opening a specially
 crafted website, an attacker could exploit this to cause a denial of
 service. (CVE-2016-1933)

 Aki Helin discovered a buffer overflow when rendering WebGL content in
 some circumstances. If a user were tricked in to opening a specially
 crafted website, an attacker could potentially exploit this to cause a
 denial of service via application crash, or execute arbitrary code with
 the privileges of the user invoking Firefox. (CVE-2016-1935)

 It was discovered that a delay was missing when focusing the protocol
 handler dialog. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to conduct
 clickjacking attacks. (CVE-2016-1937)

 Hanno Bock discovered that calculations with mp_div and mp_exptmod in NSS
 produce incorrect results in some circumstances, resulting in
 cryptographic weaknesses. (CVE-2016-1938)

 Nicholas Hurley discovered that Firefox allows for control characters to
 be set in cookie names. An attacker could potentially exploit this to
 conduct cookie injection attacks on some web servers. (CVE-2016-1939)

 It was discovered that when certain invalid URLs are pasted in to the
 addressbar, the addressbar contents may be manipulated to show the
 location of arbitrary websites. An attacker could potentially exploit this
 to conduct URL spoofing attacks. (CVE-2016-1942)

 Ronald Crane discovered three vulnerabilities through code inspection. If
 a user were tricked in to opening a specially crafted website, an attacker
 could potentially exploit these to cause a denial of service via
 application crash, or execute arbitrary code with the privileges of the
 user invoking Firefox. (CVE-2016-1944, CVE-2016-1945, CVE-2016-1946)

 Francois Marier discovered that Application Reputation lookups didn't
 work correctly, disabling warnings for potentially malicious downloads. An
 attacker could potentially exploit this by tricking a user in to
 downloading a malicious file. Other parts of the Safe Browsing feature
 were unaffected by this. (CVE-2016-1947)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"44.0.1+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"44.0.1+build2-0ubuntu0.14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"44.0.1+build2-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
