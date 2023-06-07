# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:164 (jasper)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64497");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
  script_cve_id("CVE-2007-2721", "CVE-2008-3520", "CVE-2008-3521", "CVE-2008-3522");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:164 (jasper)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"insight", value:"Multiple security vulnerabilities has been identified and fixed
in jasper:

The jpc_qcx_getcompparms function in jpc/jpc_cs.c for the JasPer
JPEG-2000 library (libjasper) before 1.900 allows remote user-assisted
attackers to cause a denial of service (crash) and possibly corrupt
the heap via malformed image files, as originally demonstrated using
imagemagick convert (CVE-2007-2721).

Multiple integer overflows in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via a crafted
image file, related to integer multiplication for memory allocation
(CVE-2008-3520).

The jas_stream_tmpfile function in libjasper/base/jas_stream.c in
JasPer 1.900.1 allows local users to overwrite arbitrary files via
a symlink attack on a tmp.XXXXXXXXXX temporary file (CVE-2008-3521).

Buffer overflow in the jas_stream_printf function in
libjasper/base/jas_stream.c in JasPer 1.900.1 might allow
context-dependent attackers to have an unknown impact via
vectors related to the mif_hdr_put function and use of vsprintf
(CVE-2008-3522).

The updated packages have been patched to prevent this.

Affected: Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:164");
  script_tag(name:"summary", value:"The remote host is missing an update to jasper
announced via advisory MDVSA-2009:164.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~4.2mdvmes2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.1~4.2mdvmes2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper1-devel", rpm:"libjasper1-devel~1.900.1~4.2mdvmes2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libjasper1-static-devel", rpm:"libjasper1-static-devel~1.900.1~4.2mdvmes2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64jasper1", rpm:"lib64jasper1~1.900.1~4.2mdvmes2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64jasper1-devel", rpm:"lib64jasper1-devel~1.900.1~4.2mdvmes2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64jasper1-static-devel", rpm:"lib64jasper1-static-devel~1.900.1~4.2mdvmes2009.0", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
