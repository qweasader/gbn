# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841517");
  script_cve_id("CVE-2013-1701", "CVE-2013-1702", "CVE-2013-1704", "CVE-2013-1705", "CVE-2013-1708", "CVE-2013-1709", "CVE-2013-1710", "CVE-2013-1711", "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717");
  script_tag(name:"creation_date", value:"2013-08-08 06:14:26 +0000 (Thu, 08 Aug 2013)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1924-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|12\.10|13\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1924-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1924-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1208039");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ubufox, unity-firefox-extension' package(s) announced via the USN-1924-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1924-1 fixed vulnerabilities in Firefox. This update provides the
corresponding updates for Ubufox and Unity Firefox Extension.

Original advisory details:

 Jeff Gilbert, Henrik Skupin, Ben Turner, Christian Holler,
 Andrew McCreight, Gary Kwong, Jan Varga and Jesse Ruderman discovered
 multiple memory safety issues in Firefox. If the user were tricked in to
 opening a specially crafted page, an attacker could possibly exploit these
 to cause a denial of service via application crash, or potentially execute
 arbitrary code with the privileges of the user invoking Firefox.
 (CVE-2013-1701, CVE-2013-1702)

 A use-after-free bug was discovered when the DOM is modified during a
 SetBody mutation event. If the user were tricked in to opening a specially
 crafted page, an attacker could potentially exploit this to execute
 arbitrary code with the privileges of the user invoking Firefox.
 (CVE-2013-1704)

 A use-after-free bug was discovered when generating a CRMF request with
 certain parameters. If the user were tricked in to opening a specially
 crafted page, an attacker could potentially exploit this to execute
 arbitrary code with the privileges of the user invoking Firefox.
 (CVE-2013-1705)

 Aki Helin discovered a crash when decoding a WAV file in some
 circumstances. An attacker could potentially exploit this to cause a
 denial of service. (CVE-2013-1708)

 It was discovered that a document's URI could be set to the URI of
 a different document. An attacker could potentially exploit this to
 conduct cross-site scripting (XSS) attacks. (CVE-2013-1709)

 A flaw was discovered when generating a CRMF request in certain
 circumstances. An attacker could potentially exploit this to conduct
 cross-site scripting (XSS) attacks, or execute arbitrary code with the
 privileges of the user invoking Firefox. (CVE-2013-1710)

 Bobby Holley discovered that XBL scopes could be used to circumvent
 XrayWrappers in certain circumstances. An attacked could potentially
 exploit this to conduct cross-site scripting (XSS) attacks or cause
 undefined behaviour. (CVE-2013-1711)

 Cody Crews discovered that some Javascript components performed security
 checks against the wrong URI, potentially bypassing same-origin policy
 restrictions. An attacker could exploit this to conduct cross-site
 scripting (XSS) attacks or install addons from a malicious site.
 (CVE-2013-1713)

 Federico Lanusse discovered that web workers could bypass cross-origin
 checks when using XMLHttpRequest. An attacker could potentially exploit
 this to conduct cross-site scripting (XSS) attacks. (CVE-2013-1714)

 Georgi Guninski and John Schoenick discovered that Java applets could
 access local files under certain circumstances. An attacker could
 potentially exploit this to steal confidential data. (CVE-2013-1717)");

  script_tag(name:"affected", value:"'ubufox, unity-firefox-extension' package(s) on Ubuntu 12.04, Ubuntu 12.10, Ubuntu 13.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"2.7-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"2.7-0ubuntu0.12.10.1", rls:"UBUNTU12.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-unity", ver:"2.4.7-0ubuntu0.2", rls:"UBUNTU12.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xul-ext-ubufox", ver:"2.7-0ubuntu0.13.04.1", rls:"UBUNTU13.04"))) {
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
