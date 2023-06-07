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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0040");
  script_cve_id("CVE-2020-36129", "CVE-2020-36130", "CVE-2020-36131", "CVE-2020-36133", "CVE-2020-36135");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-03 15:42:00 +0000 (Fri, 03 Dec 2021)");

  script_name("Mageia: Security Advisory (MGASA-2022-0040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0040");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0040.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29808");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-December/009940.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/3CU5I3APCIYTJ5MCNA4TTKLC2PLKDGKU/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aom' package(s) announced via the MGASA-2022-0040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"AOM v2.0.1 was discovered to contain a stack buffer overflow via the
component src/aom_image.c. (CVE-2020-36129)

AOM v2.0.1 was discovered to contain a NULL pointer dereference via the
component av1/av1_dx_iface.c. (CVE-2020-36130)

AOM v2.0.1 was discovered to contain a stack buffer overflow via the
component stats/rate_hist.c. (CVE-2020-36131)

AOM v2.0.1 was discovered to contain a global buffer overflow via the
component av1/encoder/partition_search.h. (CVE-2020-36133)

AOM v2.0.1 was discovered to contain a NULL pointer dereference via the
component rate_hist.c. (CVE-2020-36135)");

  script_tag(name:"affected", value:"'aom' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"aom", rpm:"aom~2.0.1~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"aom-extra-tools", rpm:"aom-extra-tools~2.0.1~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64aom-devel", rpm:"lib64aom-devel~2.0.1~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64aom2", rpm:"lib64aom2~2.0.1~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom-devel", rpm:"libaom-devel~2.0.1~3.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libaom2", rpm:"libaom2~2.0.1~3.5.mga8", rls:"MAGEIA8"))) {
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
