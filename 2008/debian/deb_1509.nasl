# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60443");
  script_cve_id("CVE-2007-4352", "CVE-2007-5392", "CVE-2007-5393");
  script_tag(name:"creation_date", value:"2008-02-28 01:09:28 +0000 (Thu, 28 Feb 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1509-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1509-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1509-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1509");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'koffice' package(s) announced via the DSA-1509-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in xpdf code that is embedded in koffice, an integrated office suite for KDE. These flaws could allow an attacker to execute arbitrary code by inducing the user to import a specially crafted PDF document. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-4352

Array index error in the DCTStream::readProgressiveDataUnit method in xpdf/Stream.cc in Xpdf 3.02pl1, as used in poppler, teTeX, KDE, KOffice, CUPS, and other products, allows remote attackers to trigger memory corruption and execute arbitrary code via a crafted PDF file.

CVE-2007-5392

Integer overflow in the DCTStream::reset method in xpdf/Stream.cc in Xpdf 3.02p11 allows remote attackers to execute arbitrary code via a crafted PDF file, resulting in a heap-based buffer overflow.

CVE-2007-5393

Heap-based buffer overflow in the CCITTFaxStream::lookChar method in xpdf/Stream.cc in Xpdf 3.02p11 allows remote attackers to execute arbitrary code via a PDF file that contains a crafted CCITTFaxDecode filter.

Updates for the old stable distribution (sarge) will be made available as soon as possible.

For the stable distribution (etch), these problems have been fixed in version 1:1.6.1-2etch2.

We recommend that you upgrade your koffice package.");

  script_tag(name:"affected", value:"'koffice' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"karbon", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kchart", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kexi", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kformula", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kivio", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kivio-data", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koffice", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koffice-data", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koffice-dbg", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koffice-dev", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koffice-doc", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koffice-doc-html", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koffice-libs", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"koshell", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kplato", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpresenter", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpresenter-data", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krita", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krita-data", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kspread", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kthesaurus", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kugar", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kword", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kword-data", ver:"1:1.6.1-2etch2", rls:"DEB4"))) {
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
