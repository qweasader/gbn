# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840992");
  script_cve_id("CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475", "CVE-2012-0477");
  script_tag(name:"creation_date", value:"2012-04-30 05:39:55 +0000 (Mon, 30 Apr 2012)");
  script_version("2023-06-21T05:06:20+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:20 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1430-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|11\.04|11\.10)");

  script_xref(name:"Advisory-ID", value:"USN-1430-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1430-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/987262");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubufox' package(s) announced via the USN-1430-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1430-1 fixed vulnerabilities in Firefox. This update provides an
updated ubufox package for use with the latest Firefox.

Original advisory details:

 Bob Clary, Christian Holler, Brian Hackett, Bobby Holley, Gary Kwong,
 Hilary Hall, Honza Bambas, Jesse Ruderman, Julian Seward, and Olli Pettay
 discovered memory safety issues affecting Firefox. If the user were tricked
 into opening a specially crafted page, an attacker could exploit these to
 cause a denial of service via application crash, or potentially execute
 code with the privileges of the user invoking Firefox. (CVE-2012-0467,
 CVE-2012-0468)

 Aki Helin discovered a use-after-free vulnerability in XPConnect. An
 attacker could potentially exploit this to execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2012-0469)

 Atte Kettunen discovered that invalid frees cause heap corruption in
 gfxImageSurface. If a user were tricked into opening a malicious Scalable
 Vector Graphics (SVG) image file, an attacker could exploit these to cause
 a denial of service via application crash, or potentially execute code with
 the privileges of the user invoking Firefox. (CVE-2012-0470)

 Anne van Kesteren discovered a potential cross-site scripting (XSS)
 vulnerability via multibyte content processing errors. With cross-site
 scripting vulnerabilities, if a user were tricked into viewing a specially
 crafted page, a remote attacker could exploit this to modify the contents,
 or steal confidential data, within the same domain. (CVE-2012-0471)

 Matias Juntunen discovered a vulnerability in Firefox's WebGL
 implementation that potentially allows the reading of illegal video memory.
 An attacker could possibly exploit this to cause a denial of service via
 application crash. (CVE-2012-0473)

 Jordi Chancel, Eddy Bordi, and Chris McGowen discovered that Firefox
 allowed the address bar to display a different website than the one the
 user was visiting. This could potentially leave the user vulnerable to
 cross-site scripting (XSS) attacks. With cross-site scripting
 vulnerabilities, if a user were tricked into viewing a specially crafted
 page, a remote attacker could exploit this to modify the contents, or steal
 confidential data, within the same domain. (CVE-2012-0474)

 Simone Fabiano discovered that Firefox did not always send correct origin
 headers when connecting to an IPv6 websites. An attacker could potentially
 use this to bypass intended access controls. (CVE-2012-0475)

 Masato Kinugawa discovered that cross-site scripting (XSS) injection is
 possible during the decoding of ISO-2022-KR and ISO-2022-CN character sets.
 With cross-site scripting vulnerabilities, if a user were tricked into
 viewing a specially crafted page, a remote attacker could exploit this to
 modify the contents, or steal confidential data, within the same domain.
 (CVE-2012-0477)

 It was discovered that certain ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ubufox' package(s) on Ubuntu 10.04, Ubuntu 11.04, Ubuntu 11.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.5-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"0.9.5-0ubuntu1", rls:"UBUNTU11.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"1.0.4-0ubuntu1", rls:"UBUNTU11.10"))) {
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
