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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3474.1");
  script_cve_id("CVE-2019-11059", "CVE-2019-11690", "CVE-2019-13103", "CVE-2019-14192", "CVE-2019-14193", "CVE-2019-14194", "CVE-2019-14195", "CVE-2019-14196", "CVE-2019-14197", "CVE-2019-14198", "CVE-2019-14200", "CVE-2019-14201", "CVE-2019-14202", "CVE-2019-14203", "CVE-2019-14204", "CVE-2019-14299", "CVE-2020-10648");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3474-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3474-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203474-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'u-boot' package(s) announced via the SUSE-SU-2020:3474-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for u-boot fixes the following issues:

Work around CVE-2019-11059 by disabling 64Bit descritptor size
(bsc#1134853)

CVE-2019-11690 (bsc#1134157), CVE-2020-10648 (bsc#1167209), CVE-2019-13103
(bsc#1143463), CVE-2019-14197 (bsc#1143821), CVE-2019-14200 (bsc#1143825),
CVE-2019-14201 (bsc#1143827), CVE-2019-14202 (bsc#1143828), CVE-2019-14203
(bsc#1143830), CVE-2019-14204 (bsc#1143831), CVE-2019-14194 (bsc#1143818),
CVE-2019-14198 (bsc#1143823), CVE-2019-14195 (bsc#1143819), CVE-2019-14196
(bsc#1143820), CVE-2019-14299 (bsc#1143824), CVE-2019-14192 (bsc#1143777),
CVE-2019-14193 (bsc#1143817).");

  script_tag(name:"affected", value:"'u-boot' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP3.");

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

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"u-boot-rpi3", rpm:"u-boot-rpi3~2016.07~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-tools", rpm:"u-boot-tools~2016.07~12.3.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"u-boot-tools-debuginfo", rpm:"u-boot-tools-debuginfo~2016.07~12.3.1", rls:"SLES12.0SP3"))) {
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
