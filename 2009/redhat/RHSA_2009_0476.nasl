# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:0476 ()
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
  script_oid("1.3.6.1.4.1.25623.1.0.63949");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-05-11 20:24:31 +0200 (Mon, 11 May 2009)");
  script_cve_id("CVE-2009-1194");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Security Advisory RHSA-2009:0476");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(3|4|5)");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:0476.

Pango is a library used for the layout and rendering of internationalized
text.

Will Drewry discovered an integer overflow flaw in Pango's
pango_glyph_string_set_size() function. If an attacker is able to pass an
arbitrarily long string to Pango, it may be possible to execute arbitrary
code with the permissions of the application calling Pango. (CVE-2009-1194)

pango and evolution28-pango users are advised to upgrade to these updated
packages, which contain a backported patch to resolve this issue. After
installing this update, you must restart your system or restart the X
server for the update to take effect. Note: Restarting the X server closes
all open applications and logs you out of your session.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-0476.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.2.5~8", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-debuginfo", rpm:"pango-debuginfo~1.2.5~8", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.2.5~8", rls:"RHENT_3")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution28-pango", rpm:"evolution28-pango~1.14.9~11.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution28-pango-debuginfo", rpm:"evolution28-pango-debuginfo~1.14.9~11.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"evolution28-pango-devel", rpm:"evolution28-pango-devel~1.14.9~11.el4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.6.0~14.4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-debuginfo", rpm:"pango-debuginfo~1.6.0~14.4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.6.0~14.4_7", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango", rpm:"pango~1.14.9~5.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-debuginfo", rpm:"pango-debuginfo~1.14.9~5.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"pango-devel", rpm:"pango-devel~1.14.9~5.el5_3", rls:"RHENT_5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
