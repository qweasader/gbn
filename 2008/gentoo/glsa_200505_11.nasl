###############################################################################
# OpenVAS Vulnerability Test
#
# Auto generated from Gentoo's XML based advisory
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2008 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54943");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-1476", "CVE-2005-1477");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_name("Gentoo Security Advisory GLSA 200505-11 (mozilla)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Several vulnerabilities in the Mozilla Suite and Firefox allow an attacker
to conduct cross-site scripting attacks or to execute arbitrary code.");
  script_tag(name:"solution", value:"All Mozilla Firefox users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=www-client/mozilla-firefox-1.0.4'

All Mozilla Firefox binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=www-client/mozilla-firefox-bin-1.0.4'

All Mozilla Suite users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-1.7.8'

All Mozilla Suite binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-bin-1.7.8'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200505-11");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=91859");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=92393");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=92394");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/mfsa2005-43.html");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200505-11.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-firefox-bin", unaffected: make_list("ge 1.0.4"), vulnerable: make_list("lt 1.0.4"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla", unaffected: make_list("ge 1.7.8"), vulnerable: make_list("lt 1.7.8"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"www-client/mozilla-bin", unaffected: make_list("ge 1.7.8"), vulnerable: make_list("lt 1.7.8"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
