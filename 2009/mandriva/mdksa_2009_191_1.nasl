# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:191-1 (OpenEXR)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66479");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-12-14 23:06:43 +0100 (Mon, 14 Dec 2009)");
  script_cve_id("CVE-2009-1720", "CVE-2009-1721", "CVE-2009-1722");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandriva Security Advisory MDVSA-2009:191-1 (OpenEXR)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2008\.0");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in OpenEXR:

Multiple integer overflows in OpenEXR 1.2.2 and 1.6.1
allow context-dependent attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via unspecified
vectors that trigger heap-based buffer overflows, related to (1)
the Imf::PreviewImage::PreviewImage function and (2) compressor
constructors.  NOTE: some of these details are obtained from third
party information (CVE-2009-1720).

The decompression implementation in the Imf::hufUncompress function in
OpenEXR 1.2.2 and 1.6.1 allows context-dependent attackers to cause a
denial of service (application crash) or possibly execute arbitrary
code via vectors that trigger a free of an uninitialized pointer
(CVE-2009-1721).

Buffer overflow in the compression implementation in OpenEXR 1.2.2
allows context-dependent attackers to cause a denial of service
(application crash) or possibly execute arbitrary code via unspecified
vectors (CVE-2009-1722).

This update provides fixes for these vulnerabilities.

Update:

Packages for 2008.0 are being provided due to extended support for
Corporate products.

Affected: 2008.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:191-1");
  script_tag(name:"summary", value:"The remote host is missing an update to OpenEXR
announced via advisory MDVSA-2009:191-1.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libOpenEXR4", rpm:"libOpenEXR4~1.4.0~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libOpenEXR-devel", rpm:"libOpenEXR-devel~1.4.0~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"OpenEXR", rpm:"OpenEXR~1.4.0~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64OpenEXR4", rpm:"lib64OpenEXR4~1.4.0~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64OpenEXR-devel", rpm:"lib64OpenEXR-devel~1.4.0~3.1mdv2008.0", rls:"MNDK_2008.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
