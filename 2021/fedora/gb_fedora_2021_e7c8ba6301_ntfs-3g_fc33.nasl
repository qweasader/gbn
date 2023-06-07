# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.818620");
  script_version("2021-10-08T08:00:55+0000");
  script_cve_id("CVE-2021-33285", "CVE-2021-33287", "CVE-2021-33289", "CVE-2021-35266", "CVE-2021-35267", "CVE-2021-35268", "CVE-2021-35269", "CVE-2021-39251", "CVE-2021-39252", "CVE-2021-39253", "CVE-2021-39254");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-08 08:00:55 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-20 17:04:00 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-24 01:43:15 +0000 (Fri, 24 Sep 2021)");
  script_name("Fedora: Security Advisory for ntfs-3g (FEDORA-2021-e7c8ba6301)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-e7c8ba6301");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/766ISTT3KCARKFUIQT7N6WV6T63XOKG3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntfs-3g'
  package(s) announced via the FEDORA-2021-e7c8ba6301 advisory.");

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

  script_tag(name:"affected", value:"'ntfs-3g' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"ntfs-3g", rpm:"ntfs-3g~2021.8.22~2.fc33", rls:"FC33"))) {
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