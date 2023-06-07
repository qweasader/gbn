# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:139 (libtorrent-rasterbar)
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
  script_oid("1.3.6.1.4.1.25623.1.0.64285");
  script_version("2022-01-20T15:10:04+0000");
  script_tag(name:"last_modification", value:"2022-01-20 15:10:04 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
  script_cve_id("CVE-2009-1760");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:139 (libtorrent-rasterbar)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_2009\.1");
  script_tag(name:"insight", value:"A security vulnerability has been identified and corrected in
libtorrent-rasterbar:

Directory traversal vulnerability in src/torrent_info.cpp in Rasterbar
libtorrent before 0.14.4, as used in firetorrent, qBittorrent, deluge
Torrent, and other applications, allows remote attackers to create
or overwrite arbitrary files via a .. (dot dot) and partial relative
pathname in Multiple File Mode list element in a .torrent file
(CVE-2009-1760).

The updated packages have been patched to prevent this.

Affected: 2009.1");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:139");
  script_tag(name:"summary", value:"The remote host is missing an update to libtorrent-rasterbar
announced via advisory MDVSA-2009:139.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"libtorrent-rasterbar1", rpm:"libtorrent-rasterbar1~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libtorrent-rasterbar-devel", rpm:"libtorrent-rasterbar-devel~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"python-libtorrent-rasterbar", rpm:"python-libtorrent-rasterbar~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64torrent-rasterbar1", rpm:"lib64torrent-rasterbar1~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64torrent-rasterbar-devel", rpm:"lib64torrent-rasterbar-devel~0.14.1~4.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
