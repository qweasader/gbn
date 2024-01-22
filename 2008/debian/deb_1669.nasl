# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61907");
  script_cve_id("CVE-2008-0016", "CVE-2008-0017", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024", "CVE-2008-5052");
  script_tag(name:"creation_date", value:"2008-11-24 22:46:43 +0000 (Mon, 24 Nov 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1669-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1669-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1669-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1669");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1669-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Xulrunner, a runtime environment for XUL applications. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0016

Justin Schuh, Tom Cross and Peter Williams discovered a buffer overflow in the parser for UTF-8 URLs, which may lead to the execution of arbitrary code.

CVE-2008-3835

'moz_bug_r_a4' discovered that the same-origin check in nsXMLDocument::OnChannelRedirect() could by bypassed.

CVE-2008-3836

'moz_bug_r_a4' discovered that several vulnerabilities in feedWriter could lead to Chrome privilege escalation.

CVE-2008-3837

Paul Nickerson discovered that an attacker could move windows during a mouse click, resulting in unwanted action triggered by drag-and-drop.

CVE-2008-4058

'moz_bug_r_a4' discovered a vulnerability which can result in Chrome privilege escalation through XPCNativeWrappers.

CVE-2008-4059

'moz_bug_r_a4' discovered a vulnerability which can result in Chrome privilege escalation through XPCNativeWrappers.

CVE-2008-4060

Olli Pettay and 'moz_bug_r_a4' discovered a Chrome privilege escalation vulnerability in XSLT handling.

CVE-2008-4061

Jesse Ruderman discovered a crash in the layout engine, which might allow the execution of arbitrary code.

CVE-2008-4062

Igor Bukanov, Philip Taylor, Georgi Guninski and Antoine Labour discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2008-4065

Dave Reed discovered that some Unicode byte order marks are stripped from Javascript code before execution, which can result in code being executed, which were otherwise part of a quoted string.

CVE-2008-4066

Gareth Heyes discovered that some Unicode surrogate characters are ignored by the HTML parser.

CVE-2008-4067

Boris Zbarsky discovered that resource: URls allow directory traversal when using URL-encoded slashes.

CVE-2008-4068

Georgi Guninski discovered that resource: URLs could bypass local access restrictions.

CVE-2008-4069

Billy Hoffman discovered that the XBM decoder could reveal uninitialised memory.

CVE-2008-4582

Liu Die Yu discovered an information leak through local shortcut files.

CVE-2008-5012

Georgi Guninski, Michal Zalewski and Chris Evan discovered that the canvas element could be used to bypass same-origin restrictions.

CVE-2008-5013

It was discovered that insufficient checks in the Flash plugin glue code could lead to arbitrary code execution.

CVE-2008-5014

Jesse Ruderman discovered that a programming error in the window.__proto__.__proto__ object could lead to arbitrary code execution.

CVE-2008-5017

It was discovered that crashes in the layout engine could lead to arbitrary code execution.

CVE-2008-5018

It was discovered that crashes in the Javascript engine could lead to arbitrary code execution.

CVE-2008-0017

Justin Schuh discovered that a buffer overflow in http-index-format ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"libmozillainterfaces-java", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmozjs0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnspr4-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-tools", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmjs-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsmjs1", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul-common", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul-dev", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul0d", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxul0d-dbg", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-xpcom", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"spidermonkey-bin", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xulrunner-gnome-support", ver:"1.8.0.15~pre080614h-0etch1", rls:"DEB4"))) {
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
