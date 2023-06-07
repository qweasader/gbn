# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:254-1 (graphviz)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66419");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2008-4555");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_name("Mandriva Security Advisory MDVSA-2009:254-1 (graphviz)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"A vulnerability was discovered and corrected in graphviz:

Stack-based buffer overflow in the push_subg function in parser.y
(lib/graph/parser.c) in Graphviz 2.20.2, and possibly earlier versions,
allows user-assisted remote attackers to cause a denial of service
(memory corruption) or execute arbitrary code via a DOT file with a
large number of Agraph_t elements (CVE-2008-4555).

This update provides a fix for this vulnerability.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:254-1");
  script_tag(name:"summary", value:"The remote host is missing an update to graphviz
announced via advisory MDVSA-2009:254-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz3", rpm:"libgraphviz3~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-devel", rpm:"libgraphviz-devel~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizlua0", rpm:"libgraphvizlua0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizperl0", rpm:"libgraphvizperl0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizphp0", rpm:"libgraphvizphp0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizpython0", rpm:"libgraphvizpython0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphvizruby0", rpm:"libgraphvizruby0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviz-static-devel", rpm:"libgraphviz-static-devel~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgraphviztcl0", rpm:"libgraphviztcl0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz3", rpm:"lib64graphviz3~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-devel", rpm:"lib64graphviz-devel~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizlua0", rpm:"lib64graphvizlua0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizperl0", rpm:"lib64graphvizperl0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizphp0", rpm:"lib64graphvizphp0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizpython0", rpm:"lib64graphvizpython0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphvizruby0", rpm:"lib64graphvizruby0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviz-static-devel", rpm:"lib64graphviz-static-devel~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64graphviztcl0", rpm:"lib64graphviztcl0~2.12~6.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
