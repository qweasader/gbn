# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0025");
  script_cve_id("CVE-2023-22809");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-28T10:19:28+0000");
  script_tag(name:"last_modification", value:"2023-03-28 10:19:28 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-26 18:26:00 +0000 (Thu, 26 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0025");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0025.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31437");
  script_xref(name:"URL", value:"https://www.sudo.ws/security/advisories/sudoedit_any/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5321");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5811-1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2QDGFCGAV5QRJCE6IXRXIS4XJHS57DDH/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the MGASA-2023-0025 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra
arguments passed in the user-provided environment variables (SUDO_EDITOR,
VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries
to the list of files to process. This can lead to privilege escalation.
Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because
a user-specified editor may contain a '--' argument that defeats a
protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file'
value. (CVE-2023-22809)");

  script_tag(name:"affected", value:"'sudo' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.9.5p2~2.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sudo-devel", rpm:"sudo-devel~1.9.5p2~2.2.mga8", rls:"MAGEIA8"))) {
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
