# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820795");
  script_version("2022-09-21T10:12:28+0000");
  script_cve_id("CVE-2021-46790", "CVE-2022-30783", "CVE-2022-30784", "CVE-2022-30785", "CVE-2022-30786", "CVE-2022-30787", "CVE-2022-30788", "CVE-2022-30789");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-21 10:12:28 +0000 (Wed, 21 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-08 02:16:00 +0000 (Wed, 08 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-25 01:08:05 +0000 (Sat, 25 Jun 2022)");
  script_name("Fedora: Security Advisory for ntfs-3g (FEDORA-2022-8fa7e5aeaf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-8fa7e5aeaf");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FAXFYIJWT5SHHRNPOJETM77EIMJ6ZP6I");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g'
  package(s) announced via the FEDORA-2022-8fa7e5aeaf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NTFS-3G is a stable, open source, GPL licensed, POSIX, read/write NTFS
driver for Linux and many other operating systems. It provides safe
handling of the Windows XP, Windows Server 2003, Windows 2000, Windows
Vista, Windows Server 2008 and Windows 7 NTFS file systems. NTFS-3G can
create, remove, rename, move files, directories, hard links, and streams,
it can read and write normal and transparently compressed files, including
streams and sparse files, it can handle special files like symbolic links,
devices, and FIFOs, ACL, extended attributes, moreover it provides full
file access right and ownership support.");

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Fedora 35.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2022.5.17~1.fc35", rls:"FC35"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);