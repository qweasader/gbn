# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841651");
  script_cve_id("CVE-2013-5609", "CVE-2013-5610", "CVE-2013-5611", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614", "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619", "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6671", "CVE-2013-6672", "CVE-2013-6673");
  script_tag(name:"creation_date", value:"2013-12-17 06:35:51 +0000 (Tue, 17 Dec 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-12-12 20:49:53 +0000 (Thu, 12 Dec 2013)");

  script_name("Ubuntu: Security Advisory (USN-2052-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2052-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2052-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1258513");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2052-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Turner, Bobby Holley, Jesse Ruderman, Christian Holler and Christoph
Diehl discovered multiple memory safety issues in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user invoking
Firefox. (CVE-2013-5609, CVE-2013-5610)

Myk Melez discovered that the doorhanger notification for web app
installation could persist between page navigations. An attacker could
potentially exploit this to conduct clickjacking attacks. (CVE-2013-5611)

Masato Kinugawa discovered that pages with missing character set encoding
information can inherit character encodings across navigations from
another domain. An attacker could potentially exploit this to conduct
cross-site scripting attacks. (CVE-2013-5612)

Daniel Veditz discovered that a sandboxed iframe could use an object
element to bypass its own restrictions. (CVE-2013-5614)

Tyson Smith and Jesse Schwartzentruber discovered a use-after-free in
event listeners. An attacker could potentially exploit this to cause a
denial of service via application crash, or execute arbitrary code with
the privileges of the user invoking Firefox. (CVE-2013-5616)

A use-after-free was discovered in the table editing interface. An
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2013-5618)

Dan Gohman discovered that binary search algorithms in Spidermonkey
used arithmetic prone to overflow in several places. However, this
is issue not believed to be exploitable. (CVE-2013-5619)

Tyson Smith and Jesse Schwartzentruber discovered a crash when inserting
an ordered list in to a document using script. An attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Firefox. (CVE-2013-6671)

Vincent Lefevre discovered that web content could access clipboard data
under certain circumstances, resulting in information disclosure.
(CVE-2013-6672)

Sijie Xia discovered that trust settings for built-in EV root certificates
were ignored under certain circumstances, removing the ability for a user
to manually untrust certificates from specific authorities.
(CVE-2013-6673)

Tyson Smith, Jesse Schwartzentruber and Atte Kettunen discovered a
use-after-free in functions for synthetic mouse movement handling. An
attacker could potentially exploit this to cause a denial of service via
application crash, or execute arbitrary code with the privileges of the
user invoking Firefox. (CVE-2013-5613)

Eric Faust discovered that GetElementIC typed array stubs can be generated
outside observed typesets. An attacker could possibly exploit this to
cause undefined behaviour with a potential security impact.
(CVE-2013-5615)

Michal Zalewski ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.12.04.2", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.12.10.2", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU13.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.13.04.2", rls:"UBUNTU13.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"26.0+build2-0ubuntu0.13.10.2", rls:"UBUNTU13.10"))) {
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
