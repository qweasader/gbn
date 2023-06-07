# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:286 (ocaml-camlimages)
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
  script_oid("1.3.6.1.4.1.25623.1.0.66089");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-10-27 01:37:56 +0100 (Tue, 27 Oct 2009)");
  script_cve_id("CVE-2009-2295", "CVE-2009-2660", "CVE-2009-3296");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:286 (ocaml-camlimages)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in
ocaml-camlimages:

Multiple integer overflows in CamlImages 2.2 and earlier might allow
context-dependent attackers to execute arbitrary code via a crafted
PNG image with large width and height values that trigger a heap-based
buffer overflow in the (1) read_png_file or (2) read_png_file_as_rgb24
function (CVE-2009-2295).

Multiple integer overflows in CamlImages 2.2 might allow
context-dependent attackers to execute arbitrary code via images
containing large width and height values that trigger a heap-based
buffer overflow, related to (1) crafted GIF files (gifread.c) and
(2) crafted JPEG files (jpegread.c), a different vulnerability than
CVE-2009-2295 (CVE-2009-2660).

Multiple integer overflows in tiffread.c in CamlImages 2.2 might allow
remote attackers to execute arbitrary code via TIFF images containing
large width and height values that trigger heap-based buffer overflows
(CVE-2009-3296).

This update fixes these vulnerabilities.

Affected: Enterprise Server 5.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:286");
  script_tag(name:"summary", value:"The remote host is missing an update to ocaml-camlimages
announced via advisory MDVSA-2009:286.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"ocaml-camlimages", rpm:"ocaml-camlimages~2.20~13.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"ocaml-camlimages-devel", rpm:"ocaml-camlimages-devel~2.20~13.1mdvmes5", rls:"MNDK_mes5")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
