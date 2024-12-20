# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841613");
  script_cve_id("CVE-2013-1739", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597", "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602", "CVE-2013-5603", "CVE-2013-5604");
  script_tag(name:"creation_date", value:"2013-11-08 05:27:15 +0000 (Fri, 08 Nov 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2010-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04|13\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2010-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2010-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1245422");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2010-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple memory safety issues were discovered in Thunderbird. If a user
were tricked in to opening a specially crafted message with scripting
enabled, an attacker could possibly exploit these to cause a denial of
service via application crash, or potentially execute arbitrary code with
the privileges of the user invoking Thunderbird. (CVE-2013-1739,
CVE-2013-5590, CVE-2013-5591)

Jordi Chancel discovered that HTML select elements could display arbitrary
content. If a user had scripting enabled, an attacker could potentially
exploit this to conduct URL spoofing or clickjacking attacks.
(CVE-2013-5593)

Abhishek Arya discovered a crash when processing XSLT data in some
circumstances. If a user had scripting enabled, an attacker could
potentially exploit this to execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2013-5604)

Dan Gohman discovered a flaw in the Javascript engine. If a user had
enabled scripting, when combined with other vulnerabilities an attacker
could possibly exploit this to execute arbitrary code with the privileges
of the user invoking Thunderbird. (CVE-2013-5595)

Ezra Pool discovered a crash on extremely large pages. If a user had
scripting enabled, an attacker could potentially exploit this to execute
arbitrary code with the privileges of the user invoking Thunderbird.
(CVE-2013-5596)

Byoungyoung Lee discovered a use-after-free when updating the offline
cache. If a user had scripting enabled, an attacker could potentially
exploit this to cause a denial of service via application crash or
execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-5597)

Multiple use-after-free flaws were discovered in Thunderbird. If a user
had scripting enabled, an attacker could potentially exploit these to
cause a denial of service via application crash or execute arbitrary code
with the privileges of the user invoking Thunderbird. (CVE-2013-5599,
CVE-2013-5600, CVE-2013-5601)

A memory corruption flaw was discovered in the Javascript engine when
using workers with direct proxies. If a user had scripting enabled, an
attacker could potentially exploit this to cause a denial of service
via application crash or execute arbitrary code with the privileges of
the user invoking Thunderbird. (CVE-2013-5602)

Abhishek Arya discovered a use-after-free when interacting with HTML
document templates. If a user had scripting enabled, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2013-5603)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04, Ubuntu 13.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.13.04.1", rls:"UBUNTU13.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:24.1.0+build1-0ubuntu0.13.10.1", rls:"UBUNTU13.10"))) {
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
