# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58471");
  script_cve_id("CVE-2007-3089", "CVE-2007-3656", "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737", "CVE-2007-3738");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1339-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1339-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1339-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1339");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-1339-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Iceape internet suite, an unbranded version of the Seamonkey Internet Suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3089

Ronen Zilberman and Michal Zalewski discovered that a timing race allows the injection of content into about:blank frames.

CVE-2007-3656

Michal Zalewski discovered that same-origin policies for wyciwyg:// documents are insufficiently enforced.

CVE-2007-3734

Bernd Mielke, Boris Zbarsky, David Baron, Daniel Veditz, Jesse Ruderman, Lukas Loehrer, Martijn Wargers, Mats Palmgren, Olli Pettay, Paul Nickerson and Vladimir Sukhoy discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2007-3735

Asaf Romano, Jesse Ruderman and Igor Bukanov discovered crashes in the javascript engine, which might allow the execution of arbitrary code.

CVE-2007-3736

moz_bug_r_a4 discovered that the addEventListener() and setTimeout() functions allow cross-site scripting.

CVE-2007-3737

moz_bug_r_a4 discovered that a programming error in event handling allows privilege escalation.

CVE-2007-3738

shutdown and moz_bug_r_a4 discovered that the XPCNativeWrapper allows the execution of arbitrary code.

The Mozilla products in the oldstable distribution (sarge) are no longer supported with security updates. You're strongly encouraged to upgrade to stable as soon as possible.

For the stable distribution (etch) these problems have been fixed in version 1.0.10~pre070720-0etch1. A build for the mips architecture is not yet available, it will be provided later.

For the unstable distribution (sid) these problems have been fixed in version 1.1.3-1.

We recommend that you upgrade your iceape packages.");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"iceape", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-browser", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-calendar", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dbg", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dev", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dom-inspector", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-gnome-support", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-mailnews", ver:"1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-calendar", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dev", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"2:1.8+1.0.10~pre070720-0etch1", rls:"DEB4"))) {
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
