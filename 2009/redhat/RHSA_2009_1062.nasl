# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:1062 ()
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
  script_oid("1.3.6.1.4.1.25623.1.0.64022");
  script_version("2022-01-24T10:51:55+0000");
  script_tag(name:"last_modification", value:"2022-01-24 10:51:55 +0000 (Mon, 24 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-05-25 20:59:33 +0200 (Mon, 25 May 2009)");
  script_cve_id("CVE-2006-1861", "CVE-2007-2754", "CVE-2009-0946");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:1062");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_2\.1");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates to FreeType announced in
advisory RHSA-2009:1062.

Tavis Ormandy of the Google Security Team discovered several integer
overflow flaws in the FreeType 2 font engine. If a user loaded a
carefully-crafted font file with an application linked against FreeType 2,
it could cause the application to crash or, possibly, execute arbitrary
code with the privileges of the user running the application.
(CVE-2009-0946)

Chris Evans discovered multiple integer overflow flaws in the FreeType font
engine. If a user loaded a carefully-crafted font file with an application
linked against FreeType, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user running
the application. (CVE-2006-1861)

An integer overflow flaw was found in the way the FreeType font engine
processed TrueType Font (TTF) files. If a user loaded a carefully-crafted
font file with an application linked against FreeType, it could cause the
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2007-2754)

Note: For the FreeType 2 font engine, the CVE-2006-1861 and CVE-2007-2754
flaws were addressed via RHSA-2006:0500 and RHSA-2007:0403 respectively.
This update provides corresponding updates for the FreeType 1 font engine,
included in the freetype packages distributed in Red Hat Enterprise Linux
2.1.

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues. The X server must be restarted
(log out, then log back in) for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1062.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"freetype", rpm:"freetype~2.0.3~17.el21", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"freetype-devel", rpm:"freetype-devel~2.0.3~17.el21", rls:"RHENT_2.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"freetype-utils", rpm:"freetype-utils~2.0.3~17.el21", rls:"RHENT_2.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
