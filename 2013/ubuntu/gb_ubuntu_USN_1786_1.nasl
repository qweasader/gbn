# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841388");
  script_cve_id("CVE-2013-0788", "CVE-2013-0789", "CVE-2013-0791", "CVE-2013-0792", "CVE-2013-0793", "CVE-2013-0794", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800");
  script_tag(name:"creation_date", value:"2013-04-05 08:22:55 +0000 (Fri, 05 Apr 2013)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.10|12\.04\ LTS|12\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1786-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1786-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1161422");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-1786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Olli Pettay, Jesse Ruderman, Boris Zbarsky, Christian Holler, Milan
Sreckovic, Joe Drew, Andrew McCreight, Randell Jesup, Gary Kwong and
Mats Palmgren discovered multiple memory safety issues affecting Firefox.
If the user were tricked into opening a specially crafted page, an
attacker could possibly exploit these to cause a denial of service via
application crash, or potentially execute code with the privileges of the
user invoking Firefox. (CVE-2013-0788, CVE-2013-0789)

Ambroz Bizjak discovered an out-of-bounds array read in the
CERT_DecodeCertPackage function of the Network Security Services (NSS)
library when decoding certain certificates. An attacker could potentially
exploit this to cause a denial of service via application crash.
(CVE-2013-0791)

Tobias Schula discovered an information leak in Firefox when the
gfx.color_management.enablev4 preference is enabled. If the user were
tricked into opening a specially crafted image, an attacker could
potentially exploit this to steal confidential data. By default, the
gfx.color_management.enablev4 preference is not enabled in Ubuntu.
(CVE-2013-0792)

Mariusz Mlynski discovered that timed history navigations could be used to
load arbitrary websites with the wrong URL displayed in the addressbar. An
attacker could exploit this to conduct cross-site scripting (XSS) or
phishing attacks. (CVE-2013-0793)

It was discovered that the origin indication on tab-modal dialog boxes
could be removed, which could allow an attacker's dialog to be displayed
over another sites content. An attacker could exploit this to conduct
phishing attacks. (CVE-2013-0794)

Cody Crews discovered that the cloneNode method could be used to
bypass System Only Wrappers (SOW) to clone a protected node and bypass
same-origin policy checks. An attacker could potentially exploit this to
steal confidential data or execute code with the privileges of the user
invoking Firefox. (CVE-2013-0795)

A crash in WebGL rendering was discovered in Firefox. An attacker could
potentially exploit this to execute code with the privileges of the user
invoking Firefox. This issue only affects users with Intel graphics
drivers. (CVE-2013-0796)

Abhishek Arya discovered an out-of-bounds write in the Cairo graphics
library. An attacker could potentially exploit this to execute code with
the privileges of the user invoking Firefox. (CVE-2013-0800)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 10.04, Ubuntu 11.10, Ubuntu 12.04, Ubuntu 12.10.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.10.04.3", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.11.10.3", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.12.04.3", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"20.0+build1-0ubuntu0.12.10.3", rls:"UBUNTU12.10"))) {
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
