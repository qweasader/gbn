# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60794");
  script_cve_id("CVE-2007-5745", "CVE-2007-5746", "CVE-2007-5747", "CVE-2008-0320");
  script_tag(name:"creation_date", value:"2008-04-21 18:40:14 +0000 (Mon, 21 Apr 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1547)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1547");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1547");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1547");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openoffice.org' package(s) announced via the DSA-1547 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security related problems have been discovered in OpenOffice.org, the free office suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-5745, CVE-2007-5747 Several bugs have been discovered in the way OpenOffice.org parses Quattro Pro files that may lead to a overflow in the heap potentially leading to the execution of arbitrary code.

CVE-2007-5746

Specially crafted EMF files can trigger a buffer overflow in the heap that may lead to the execution of arbitrary code.

CVE-2008-0320

A bug has been discovered in the processing of OLE files that can cause a buffer overflow in the heap potentially leading to the execution of arbitrary code.

Recently reported problems in the ICU library are fixed in separate libicu packages with DSA 1511 against which OpenOffice.org is linked.

For the old stable distribution (sarge) these problems have been fixed in version 1.1.3-9sarge9.

For the stable distribution (etch) these problems have been fixed in version 2.0.4.dfsg.2-7etch5.

For the testing (lenny) and unstable (sid) distributions these problems have been fixed in version 2.4.0~ooh680m5-1.

We recommend that you upgrade your openoffice.org packages.");

  script_tag(name:"affected", value:"'openoffice.org' package(s) on Debian 3.1, Debian 4.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-bin", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ar", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eu", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gl", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-kn", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-mimelnk", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-thesaurus-en-us", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"1.1.3-9sarge9", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"broffice.org", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmythes-dev", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-base", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-calc", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-common", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-core", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dbg", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dev-doc", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-draw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-dtd-officedocument1.0", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-evolution", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-mobiledev", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-filter-so52", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gcj", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gnome", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-gtk-gnome", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-cs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-da", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-de", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-dz", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-gb", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-en-us", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-es", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-et", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-fr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hi-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-hu", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-it", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ja", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-km", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ko", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-nl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-pt-br", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-ru", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-sv", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-cn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-help-zh-tw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-impress", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-java-common", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-kde", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-af", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-as-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-be-by", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bg", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-br", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-bs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ca", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-cy", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-da", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-de", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-dz", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-el", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-gb", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-en-za", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-eo", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-es", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-et", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fa", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fi", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-fr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ga", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-gu-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-he", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hi-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-hu", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-it", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ja", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ka", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-km", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ko", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ku", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lo", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lt", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-lv", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-mk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ml-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nb", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ne", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-nr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ns", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-or-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pa-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-pt-br", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ru", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-rw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sl", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sr-cs", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ss", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-st", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-sv", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ta-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-te-in", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tg", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-th", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-tr", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ts", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-uk", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-ve", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-vi", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-xh", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-za", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-cn", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zh-tw", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-l10n-zu", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-math", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-officebean", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-api-tests", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-qa-tools", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openoffice.org-writer", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-uno", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ttf-opensymbol", ver:"2.0.4.dfsg.2-7etch5", rls:"DEB4"))) {
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
