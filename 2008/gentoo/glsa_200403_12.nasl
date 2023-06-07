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
  script_oid("1.3.6.1.4.1.25623.1.0.54537");
  script_cve_id("CVE-2003-1201");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2022-01-18T14:26:25+0000");
  script_tag(name:"last_modification", value:"2022-01-18 14:26:25 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
  script_name("Gentoo Security Advisory GLSA 200403-12 (openldap)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 E-Soft Inc.");
  script_family("Gentoo Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/gentoo", "ssh/login/pkg");
  script_tag(name:"insight", value:"A failed password operation can cause the OpenLDAP slapd server, if it is
using the back-ldbm backend, to free memory that was never allocated.");
  script_tag(name:"solution", value:"OpenLDAP users should upgrade to version 2.1.17 or later:

    # emerge sync

    # emerge -pv '>=net-nds/openldap-2.1.17'
    # emerge '>=net-nds/openldap-2.1.17'");

  script_xref(name:"URL", value:"http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-12");
  script_xref(name:"URL", value:"http://bugs.gentoo.org/show_bug.cgi?id=26728");
  script_xref(name:"URL", value:"http://www.openldap.org/its/index.cgi?findid=2390");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory GLSA 200403-12.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("pkg-lib-gentoo.inc");
include("revisions-lib.inc");

res = "";
report = "";
report = "";
if ((res = ispkgvuln(pkg:"net-nds/openldap", unaffected: make_list("ge 2.1.17"), vulnerable: make_list("le 2.1.16"))) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}