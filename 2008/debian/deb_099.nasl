# SPDX-FileCopyrightText: 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53761");
  script_cve_id("CVE-2002-0006");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Debian Security Advisory DSA 099-1 (XChat)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB2\.2");
  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20099-1");
  script_tag(name:"insight", value:"zen-parse found a vulnerability in the XChat IRC client that allows an
attacker to take over the users IRC session.

It is possible to trick XChat IRC clients into sending arbitrary
commands to the IRC server they are on, potentially allowing social
engineering attacks, channel takeovers, and denial of service.  This
problem exists in versions 1.4.2 and 1.4.3.  Later versions of XChat
are vulnerable as well, but this behaviour is controlled by the
configuration variable >>percascii<<, which defaults to 0.  If it is set
to 1 then the problem becomes apparent in 1.6/1.8 a swell.

This problem has been fixed in upstream version 1.8.7 and in version
1.4.3-1 for the current stable Debian release (2.2) with a patch
provided from the upstream author Peter Zelezny.  We recommend that
you upgrade your XChat packages immediately, since this problem is
already actively being exploited.");
  script_tag(name:"summary", value:"The remote host is missing an update to XChat
announced via advisory DSA 099-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"We recommend that you upgrade your xchat packages.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"xchat-common", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xchat-gnome", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xchat-text", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"xchat", ver:"1.4.3-1", rls:"DEB2.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
