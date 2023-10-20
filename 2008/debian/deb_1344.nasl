# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58516");
  script_cve_id("CVE-2007-3844", "CVE-2007-3845", "CVE-2007-4041");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2023-07-05T05:06:16+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:16 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1344");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1344");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1344");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceweasel' package(s) announced via the DSA-1344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceweasel web browser, an unbranded version of the Firefox browser. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3844

moz_bug_r_a4 discovered that a regression in the handling of about:blank windows used by addons may lead to an attacker being able to modify the content of web sites.

CVE-2007-3845

Jesper Johansson discovered that missing sanitising of double-quotes and spaces in URIs passed to external programs may allow an attacker to pass arbitrary arguments to the helper program if the user is tricked into opening a malformed web page.

The Mozilla products in the oldstable distribution (sarge) are no longer supported with security updates.

For the stable distribution (etch) these problems have been fixed in version 2.0.0.6-0etch1.

For the unstable distribution (sid) these problems have been fixed in version 2.0.0.6-1.

We recommend that you upgrade your iceweasel packages.");

  script_tag(name:"affected", value:"'iceweasel' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-dom-inspector", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firefox-gnome-support", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dbg", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-dom-inspector", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceweasel-gnome-support", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"2.0.0.6-0etch1", rls:"DEB4"))) {
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
