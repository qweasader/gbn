# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122442");
  script_cve_id("CVE-2008-6552");
  script_tag(name:"creation_date", value:"2015-10-08 11:45:28 +0000 (Thu, 08 Oct 2015)");
  script_version("2022-04-05T06:57:19+0000");
  script_tag(name:"last_modification", value:"2022-04-05 06:57:19 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-1337)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-1337");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-1337.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gfs2-utils' package(s) announced via the ELSA-2009-1337 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.1.62-1]
- Fix man page references to fsck.gfs2.
- Resolves: rhbz#477072

[0.1.61-1]
- fsck.gfs2 no longer segfaults when fixing 'EA leaf block type' problems.
- Resolves: rhbz#510758

[0.1.60-1]
- When '/' is a gfs2 file system it is now properly mounted without an error.
- Resolves: rhbz#507893

[0.1.59-1]
- gfs_convert -vy now works properly on a ppc system.
- Resolves: rhbz#506629

[0.1.58-1]
- Fixed an issue with the gfs2_edit savemeta function not saving blocks of type
 2.
- Resolves: rhbz#502056

[0.1.57-1]
- A gfs filesystems metadata is now properly copied with 'gfs2_edit savemeta'
- Resolves: rhbz#501732

[0.1.56-1]
- gfs2_fsck now properly fixes journal sequence numbers
- The debugfs mount point has been randomized to prevent symlink attacks
- Resolves: rhbz#498646 rhbz#498950

[0.1.55-1]
- gfs2_convert now properly frees blocks when removing a file with a height
 greater than 1
- Updated man pages
- Added options to gfs2_tool df to provide more human readable output
- GFS2 utilities now use and provide filesystem UUID
- gfs2_fsck now uses the proper return codes
- gfs2_edit has been updated
- gfs2_tool df no longer segfaults on a non-4k block size
- gfs2_grow no longer references the '-r' option
- gfs2_convert no longer causes filesystem corruption
- gfs2_edit has been improved to help differentiate between zero-data and
 non-zero data from pointers
- gfs2_edit now properly saves the per-node quota files
- A segfault in gfs2_fsck as been fixed
- Resolves: rhbz#474707 rhbz#477072 rhbz#480833 rhbz#242701 rhbz#474705 rhbz#483799 rhbz#485761 rhbz#486034 rhbz#490136 rhbz#483799 rhbz#496330");

  script_tag(name:"affected", value:"'gfs2-utils' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"gfs2-utils", rpm:"gfs2-utils~0.1.62~1.el5", rls:"OracleLinux5"))) {
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
