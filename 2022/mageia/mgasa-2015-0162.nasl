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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0162");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0162)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0162");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0162.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15644");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14516");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2015-0116.html");
  script_xref(name:"URL", value:"https://ml.mageia.org/l/arc/qa-discuss/2015-03/msg00399.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'setup' package(s) announced via the MGASA-2015-0162 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated setup package fixes security issue

An issue has been identified in Mageia 4's setup package where the
/etc/shadow and /etc/gshadow files containing password hashes were created
with incorrect permissions, making them world-readable (mga#14516).

This update fixes this issue by enforcing that those files are owned by
the root user and shadow group, and are only readable by those two entities.

Note that this issue only affected new Mageia 4 installations. Systems that
were updated from previous Mageia versions were not affected.

This update was already issued as MGASA-2015-0116, but the latter was withdrawn
as it generated .rpmnew files for critical configuration files, and rpmdrake
might propose the user to use those basically empty files, thus leading to
loss of passwords or partition table. This new update ensures that such .rpmnew
files are not kept after the update.");

  script_tag(name:"affected", value:"'setup' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"setup", rpm:"setup~2.7.20~9.4.mga4", rls:"MAGEIA4"))) {
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
