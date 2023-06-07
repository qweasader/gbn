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
  script_oid("1.3.6.1.4.1.25623.1.0.853956");
  script_version("2021-08-26T12:01:05+0000");
  script_cve_id("CVE-2020-24370", "CVE-2020-24371");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-08-26 12:01:05 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-26 16:15:00 +0000 (Sat, 26 Sep 2020)");
  script_tag(name:"creation_date", value:"2021-07-13 03:05:25 +0000 (Tue, 13 Jul 2021)");
  script_name("openSUSE: Security Advisory for lua53 (openSUSE-SU-2021:2196-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2196-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EASBVV4MIBIGZHO5CD23ITJBJVVHVDEU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lua53'
  package(s) announced via the openSUSE-SU-2021:2196-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for lua53 fixes the following issues:

     Update to version 5.3.6:

  - CVE-2020-24371: lgc.c mishandles the interaction between barriers and
       the sweep phase, leading to a memory access violation involving
       collectgarbage (bsc#1175449)

  - CVE-2020-24370: ldebug.c allows a negation overflow and segmentation
       fault in getlocal and setlocal (bsc#1175448)

  - Long brackets with a huge number of &#x27 =&#x27  overflow some internal buffer
       arithmetic.");

  script_tag(name:"affected", value:"'lua53' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5", rpm:"liblua5_3-5~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-debuginfo", rpm:"liblua5_3-5-debuginfo~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53", rpm:"lua53~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-debuginfo", rpm:"lua53-debuginfo~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-debugsource", rpm:"lua53-debugsource~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-devel", rpm:"lua53-devel~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua53-doc", rpm:"lua53-doc~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-32bit", rpm:"liblua5_3-5-32bit~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblua5_3-5-32bit-debuginfo", rpm:"liblua5_3-5-32bit-debuginfo~5.3.6~3.6.1", rls:"openSUSELeap15.3"))) {
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