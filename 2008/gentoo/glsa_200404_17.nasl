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
  script_oid("1.3.6.1.4.1.25623.1.0.54556");
  script_version("2022-05-13T11:28:10+0000");
  script_tag(name:"last_modification", value:"2022-05-13 11:28:10 +0000 (Fri, 13 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_cve_id("CVE-2004-0403");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Gentoo Security Advisory GLSA 200404-17 (ipsec-utils)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"racoon, which is included in the ipsec-tools and iputils packages in
Portage, does not check the length of ISAKMP headers. Attackers may be
able to craft an ISAKMP header of sufficient length to consume all
available system resources, causing a Denial of Service.");
  script_tag(name:"solution", value:"ipsec-tools users should upgrade to version 0.2.5 or later:

    # emerge sync

    # emerge -pv '>=net-firewall/ipsec-tools-0.3.1'
    # emerge '>=net-firewall/ipsec-tools-0.3.1'

iputils users should upgrade to version 021109-r3 or later:

    # emerge sync

    # emerge -pv '>=net-misc/iputils-021109-r3'
    # emerge '>=net-misc/iputils-021109-r3'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200404-17");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10172");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=48847");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200404-17.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-firewall/ipsec-tools", unaffected: make_list("ge 0.3.1"), vulnerable: make_list("lt 0.3.1"))) != NULL) {
    report += res;
}
if ((res = ispkgvuln(pkg:"net-misc/iputils", unaffected: make_list("eq 021109-r3"), vulnerable: make_list("eq 021109-r1"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
