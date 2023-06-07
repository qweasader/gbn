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
  script_oid("1.3.6.1.4.1.25623.1.0.854824");
  script_version("2022-08-03T10:11:15+0000");
  script_cve_id("CVE-2022-32212", "CVE-2022-32213", "CVE-2022-32214", "CVE-2022-32215");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-03 10:11:15 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-07-22 01:01:27 +0000 (Fri, 22 Jul 2022)");
  script_name("openSUSE: Security Advisory for nodejs16 (SUSE-SU-2022:2491-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2491-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/YKAPPLAXG4CJHMP2ZZPVH3DQU6WGERIO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs16'
  package(s) announced via the SUSE-SU-2022:2491-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs16 fixes the following issues:

  - CVE-2022-32212: Fixed DNS rebinding in --inspect via invalid IP
       addresses (bsc#1201328).

  - CVE-2022-32213: Fixed HTTP request smuggling due to flawed parsing of
       Transfer-Encoding (bsc#1201325).

  - CVE-2022-32214: Fixed HTTP request smuggling due to improper delimiting
       of header fields (bsc#1201326).

  - CVE-2022-32215: Fixed HTTP request smuggling due to incorrect parsing of
       multi-line Transfer-Encoding (bsc#1201327).");

  script_tag(name:"affected", value:"'nodejs16' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"corepack16", rpm:"corepack16~16.16.0~150400.3.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16", rpm:"nodejs16~16.16.0~150400.3.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-debuginfo", rpm:"nodejs16-debuginfo~16.16.0~150400.3.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-debugsource", rpm:"nodejs16-debugsource~16.16.0~150400.3.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-devel", rpm:"nodejs16-devel~16.16.0~150400.3.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm16", rpm:"npm16~16.16.0~150400.3.3.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs16-docs", rpm:"nodejs16-docs~16.16.0~150400.3.3.2", rls:"openSUSELeap15.4"))) {
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