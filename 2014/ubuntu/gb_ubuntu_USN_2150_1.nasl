# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841757");
  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");
  script_tag(name:"creation_date", value:"2014-03-20 04:19:40 +0000 (Thu, 20 Mar 2014)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-10 18:42:00 +0000 (Mon, 10 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-2150-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2150-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2150-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1291982");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2150-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij, Jesse Ruderman, Dan
Gohman, Christoph Diehl, Gregor Wagner, Gary Kwong, Luke Wagner, Rob
Fletcher and Makoto Kato discovered multiple memory safety issues in
Firefox. If a user were tricked in to opening a specially crafted website,
an attacker could potentially exploit these to cause a denial of service
via application crash, or execute arbitrary code with the privileges of
the user invoking Firefox. (CVE-2014-1493, CVE-2014-1494)

Atte Kettunen discovered an out-of-bounds read during WAV file decoding.
An attacker could potentially exploit this to cause a denial of service
via application crash. (CVE-2014-1497)

David Keeler discovered that crypto.generateCRFMRequest did not correctly
validate all arguments. An attacker could potentially exploit this to
cause a denial of service via application crash. (CVE-2014-1498)

Ehsan Akhgari discovered that the WebRTC permission dialog can display
the wrong originating site information under some circumstances. An
attacker could potentially exploit this by tricking a user in order to
gain access to their webcam or microphone. (CVE-2014-1499)

Tim Philipp Schafers and Sebastian Neef discovered that onbeforeunload
events used with page navigations could make the browser unresponsive
in some circumstances. An attacker could potentially exploit this to
cause a denial of service. (CVE-2014-1500)

Jeff Gilbert discovered that WebGL content could manipulate content from
another sites WebGL context. An attacker could potentially exploit this
to conduct spoofing attacks. (CVE-2014-1502)

Nicolas Golubovic discovered that CSP could be bypassed for data:
documents during session restore. An attacker could potentially exploit
this to conduct cross-site scripting attacks. (CVE-2014-1504)

Robert O'Callahan discovered a mechanism for timing attacks involving
SVG filters and displacements input to feDisplacementMap. An attacker
could potentially exploit this to steal confidential information across
domains. (CVE-2014-1505)

Tyson Smith and Jesse Schwartzentruber discovered an out-of-bounds read
during polygon rendering in MathML. An attacker could potentially exploit
this to steal confidential information across domains. (CVE-2014-1508)

John Thomson discovered a memory corruption bug in the Cairo graphics
library. If a user had a malicious extension installed, an attacker could
potentially exploit this to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2014-1509)

Mariusz Mlynski discovered that web content could open a chrome privileged
page and bypass the popup blocker in some circumstances. An attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2014-1510, CVE-2014-1511)

It was discovered that memory pressure during garbage collection ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"28.0+build2-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"28.0+build2-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"28.0+build2-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
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
