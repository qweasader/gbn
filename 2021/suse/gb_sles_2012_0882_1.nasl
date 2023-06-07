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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0882.1");
  script_cve_id("CVE-2012-2677");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0882-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4|SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0882-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120882-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'boost' package(s) announced via the SUSE-SU-2012:0882-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two problems have been fixed in the boost library:

 * boost::pool's ordered_malloc could have overflowed when calculating the allocation size (CVE-2012-2677).
 * fully qualify the boost::date_time::dst_adjustment_offsets (non security).

Security Issue reference:

 * CVE-2012-2677
>");

  script_tag(name:"affected", value:"'boost' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Desktop 11-SP1, SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2, SUSE Linux Enterprise Software Development Kit 11-SP1, SUSE Linux Enterprise Software Development Kit 11-SP2.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"boost", rpm:"boost~1.33.1~17.15.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-32bit", rpm:"boost-32bit~1.33.1~17.15.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-64bit", rpm:"boost-64bit~1.33.1~17.15.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-devel", rpm:"boost-devel~1.33.1~17.15.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-devel-64bit", rpm:"boost-devel-64bit~1.33.1~17.15.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"boost-doc", rpm:"boost-doc~1.33.1~17.15.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"boost-license", rpm:"boost-license~1.36.0~12.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_36_0", rpm:"libboost_program_options1_36_0~1.36.0~12.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_36_0", rpm:"libboost_regex1_36_0~1.36.0~12.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_36_0", rpm:"libboost_signals1_36_0~1.36.0~12.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"boost-license", rpm:"boost-license~1.36.0~12.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_program_options1_36_0", rpm:"libboost_program_options1_36_0~1.36.0~12.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_regex1_36_0", rpm:"libboost_regex1_36_0~1.36.0~12.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libboost_signals1_36_0", rpm:"libboost_signals1_36_0~1.36.0~12.3.1", rls:"SLES11.0SP2"))) {
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
