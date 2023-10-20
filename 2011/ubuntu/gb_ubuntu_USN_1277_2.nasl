# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840815");
  script_cve_id("CVE-2011-3648", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3654", "CVE-2011-3655");
  script_tag(name:"creation_date", value:"2011-11-25 06:30:50 +0000 (Fri, 25 Nov 2011)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1277-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1277-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1277-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/887339");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozvoikko, ubufox' package(s) announced via the USN-1277-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1277-1 fixed vulnerabilities in Firefox. This update provides updated
Mozvoikko and ubufox packages for use with Firefox 8.

Original advisory details:

 Yosuke Hasegawa discovered that the Mozilla browser engine mishandled
 invalid sequences in the Shift-JIS encoding. It may be possible to trigger
 this crash without the use of debugging APIs, which might allow malicious
 websites to exploit this vulnerability. An attacker could possibly use this
 flaw this to steal data or inject malicious scripts into web content.
 (CVE-2011-3648)

 Marc Schoenefeld discovered that using Firebug to profile a JavaScript file
 with many functions would cause Firefox to crash. An attacker might be able
 to exploit this without using the debugging APIs, which could potentially
 remotely crash the browser, resulting in a denial of service.
 (CVE-2011-3650)

 Jason Orendorff, Boris Zbarsky, Gregg Tavares, Mats Palmgren, Christian
 Holler, Jesse Ruderman, Simona Marcu, Bob Clary, and William McCloskey
 discovered multiple memory safety bugs in the browser engine used in
 Firefox and other Mozilla-based products. An attacker might be able to use
 these flaws to execute arbitrary code with the privileges of the user
 invoking Firefox or possibly crash the browser resulting in a denial of
 service. (CVE-2011-3651)

 It was discovered that Firefox could be caused to crash under certain
 conditions, due to an unchecked allocation failure, resulting in a denial
 of service. It might also be possible to execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2011-3652)

 Aki Helin discovered that Firefox does not properly handle links from SVG
 mpath elements to non-SVG elements. An attacker could use this
 vulnerability to crash Firefox, resulting in a denial of service, or
 possibly execute arbitrary code with the privileges of the user invoking
 Firefox. (CVE-2011-3654)

 It was discovered that an internal privilege check failed to respect the
 NoWaiverWrappers introduced with Firefox 4. An attacker could possibly use
 this to gain elevated privileges within the browser for web content.
 (CVE-2011-3655)");

  script_tag(name:"affected", value:"'mozvoikko, ubufox' package(s) on Ubuntu 11.04, Ubuntu 11.10.");

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

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"1.10.0-0ubuntu0.11.04.3", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.2-0ubuntu0.11.04.2", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-mozvoikko", ver:"1.10.0-0ubuntu2.1", rls:"UBUNTU11.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"1.0-0ubuntu2.1", rls:"UBUNTU11.10"))) {
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
