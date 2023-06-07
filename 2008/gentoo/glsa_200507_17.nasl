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
  script_oid("1.3.6.1.4.1.25623.1.0.54993");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2005-0989");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Gentoo Security Advisory GLSA 200507-17 (thunderbird)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"Several vulnerabilities in Mozilla Thunderbird allow attacks ranging from
execution of script code with elevated privileges to information leak.");
  script_tag(name:"solution", value:"All Mozilla Thunderbird users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=mail-client/mozilla-thunderbird-1.0.5'

All Mozilla Thunderbird binary users should upgrade to the latest version:

    # emerge --sync
    # emerge --ask --oneshot --verbose
'>=mail-client/mozilla-thunderbird-bin-1.0.5'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200507-17");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/12988");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/15495");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=98855");
  script_xref(name:"URL", value:"http://www.mozilla.org/projects/security/known-vulnerabilities.html#Thunderbird");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200507-17.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird", unaffected: make_list("ge 1.0.5"), vulnerable: make_list("lt 1.0.5"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"mail-client/mozilla-thunderbird-bin", unaffected: make_list("ge 1.0.5"), vulnerable: make_list("lt 1.0.5"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}