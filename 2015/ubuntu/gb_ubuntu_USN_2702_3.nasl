# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842419");
  script_cve_id("CVE-2015-4473", "CVE-2015-4474", "CVE-2015-4475", "CVE-2015-4477", "CVE-2015-4478", "CVE-2015-4479", "CVE-2015-4480", "CVE-2015-4484", "CVE-2015-4485", "CVE-2015-4486", "CVE-2015-4493");
  script_tag(name:"creation_date", value:"2015-08-21 05:49:10 +0000 (Fri, 21 Aug 2015)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2702-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2702-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2702-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1485741");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-2702-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2702-1 fixed vulnerabilities in Firefox. After upgrading, some users
in the US reported that their default search engine switched to Yahoo.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Gary Kwong, Christian Holler, Byron Campen, Tyson Smith, Bobby Holley,
 Chris Coulson, and Eric Rahm discovered multiple memory safety issues in
 Firefox. If a user were tricked in to opening a specially crafted website,
 an attacker could potentially exploit these to cause a denial of service
 via application crash, or execute arbitrary code with the privileges of
 the user invoking Firefox. (CVE-2015-4473, CVE-2015-4474)

 Aki Helin discovered an out-of-bounds read when playing malformed MP3
 content in some circumstances. If a user were tricked in to opening a
 specially crafted website, an attacker could potentially exploit this to
 obtain sensitive information, cause a denial of service via application
 crash, or execute arbitrary code with the privileges of the user invoking
 Firefox. (CVE-2015-4475)

 A use-after-free was discovered during MediaStream playback in some
 circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service via application crash or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2015-4477)

 Andre Bargull discovered that non-configurable properties on javascript
 objects could be redefined when parsing JSON. If a user were tricked in to
 opening a specially crafted website, an attacker could potentially exploit
 this to bypass same-origin restrictions. (CVE-2015-4478)

 Multiple integer overflows were discovered in libstagefright. If a user
 were tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service via application
 crash, or execute arbitrary code with the privileges of the user invoking
 Firefox. (CVE-2015-4479, CVE-2015-4480, CVE-2015-4493)

 Jukka Jylanki discovered a crash that occurs because javascript does not
 properly gate access to Atomics or SharedArrayBuffers in some
 circumstances. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service. (CVE-2015-4484)

 Abhishek Arya discovered 2 buffer overflows in libvpx when decoding
 malformed WebM content in some circumstances. If a user were tricked in
 to opening a specially crafted website, an attacker could potentially
 exploit these to cause a denial of service via application crash, or
 execute arbitrary code with the privileges of the user invoking Firefox.
 (CVE-2015-4485, CVE-2015-4486)

 Ronald Crane reported 3 security issues. If a user were tricked in to
 opening a specially crafted website, an attacker could potentially
 exploit these, in combination with another ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"40.0+build4-0ubuntu0.12.04.4", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"40.0+build4-0ubuntu0.14.04.4", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"40.0+build4-0ubuntu0.15.04.4", rls:"UBUNTU15.04"))) {
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
