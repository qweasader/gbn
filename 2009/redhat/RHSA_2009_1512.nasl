# OpenVAS Vulnerability Test
# Description: Auto-generated from advisory RHSA-2009:1512 ()
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
  script_oid("1.3.6.1.4.1.25623.1.0.66017");
  script_version("2022-01-21T08:36:19+0000");
  script_tag(name:"last_modification", value:"2022-01-21 08:36:19 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-10-19 21:50:22 +0200 (Mon, 19 Oct 2009)");
  script_cve_id("CVE-2009-0791", "CVE-2009-1188", "CVE-2009-3604", "CVE-2009-3608", "CVE-2009-3609");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("RedHat Security Advisory RHSA-2009:1512");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_4");
  script_tag(name:"solution", value:"Please note that this update is available via
Red Hat Network.  To use Red Hat Network, launch the Red
Hat Update Agent with the following command: up2date");
  script_tag(name:"summary", value:"The remote host is missing updates announced in
advisory RHSA-2009:1512.

The kdegraphics packages contain applications for the K Desktop
Environment, including KPDF, a viewer for Portable Document Format (PDF)
files.

Multiple integer overflow flaws were found in KPDF. An attacker could
create a malicious PDF file that would cause KPDF to crash or, potentially,
execute arbitrary code when opened. (CVE-2009-0791, CVE-2009-1188,
CVE-2009-3604, CVE-2009-3608, CVE-2009-3609)

Red Hat would like to thank Adam Zabrocki for reporting the CVE-2009-3604
issue, and Chris Rohlf for reporting the CVE-2009-3608 issue.

Users are advised to upgrade to these updated packages, which contain a
backported patch to resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1512.html");
  script_xref(name:"URL", value:"http://www.redhat.com/security/updates/classification/#important");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"kdegraphics", rpm:"kdegraphics~3.3.1~15.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-debuginfo", rpm:"kdegraphics-debuginfo~3.3.1~15.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"kdegraphics-devel", rpm:"kdegraphics-devel~3.3.1~15.el4_8.2", rls:"RHENT_4")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
