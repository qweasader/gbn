# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842501");
  script_cve_id("CVE-2015-6755", "CVE-2015-6757", "CVE-2015-6759", "CVE-2015-6761", "CVE-2015-6762", "CVE-2015-6763", "CVE-2015-7834");
  script_tag(name:"creation_date", value:"2015-10-26 14:33:08 +0000 (Mon, 26 Oct 2015)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2770-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU15\.10");

  script_xref(name:"Advisory-ID", value:"USN-2770-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2770-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oxide-qt' package(s) announced via the USN-2770-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2770-1 fixed vulnerabilities in Oxide in Ubuntu 14.04 LTS and Ubuntu
15.04. This update provides the corresponding updates for Ubuntu 15.10.

Original advisory details:

 It was discovered that ContainerNode::parserInsertBefore in Blink would
 incorrectly proceed with a DOM tree insertion in some circumstances. If a
 user were tricked in to opening a specially crafted website, an attacker
 could potentially exploit this to bypass same origin restrictions.
 (CVE-2015-6755)

 A use-after-free was discovered in the service worker implementation in
 Chromium. If a user were tricked in to opening a specially crafted
 website, an attacker could potentially exploit this to cause a denial of
 service via application crash, or execute arbitrary code with the
 privileges of the user invoking the program. (CVE-2015-6757)

 It was discovered that Blink did not ensure that the origin of
 LocalStorage resources are considered unique. If a user were tricked in to
 opening a specially crafted website, an attacker could potentially exploit
 this to obtain sensitive information. (CVE-2015-6759)

 A race condition and memory corruption was discovered in FFmpeg. If a user
 were tricked in to opening a specially crafted website, an attacker could
 potentially exploit this to cause a denial of service via renderer crash,
 or execute arbitrary code with the privileges of the sandboxed render
 process. (CVE-2015-6761)

 It was discovered that CSSFontFaceSrcValue::fetch in Blink did not use
 CORS in some circumstances. If a user were tricked in to opening a
 specially crafted website, an attacker could potentially exploit this to
 bypass same origin restrictions. (CVE-2015-6762)

 Multiple security issues were discovered in Chromium. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to read uninitialized memory, cause a denial
 of service via application crash or execute arbitrary code with the
 privileges of the user invoking the program. (CVE-2015-6763)

 Multiple security issues were discovered in V8. If a user were tricked
 in to opening a specially crafted website, an attacker could potentially
 exploit these to read uninitialized memory, cause a denial of service via
 renderer crash or execute arbitrary code with the privileges of the
 sandboxed render process. (CVE-2015-7834)");

  script_tag(name:"affected", value:"'oxide-qt' package(s) on Ubuntu 15.10.");

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

if(release == "UBUNTU15.10") {

  if(!isnull(res = isdpkgvuln(pkg:"liboxideqtcore0", ver:"1.10.3-0ubuntu0.15.10.1", rls:"UBUNTU15.10"))) {
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
