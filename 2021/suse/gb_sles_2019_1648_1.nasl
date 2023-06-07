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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1648.1");
  script_cve_id("CVE-2019-11459");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-03-06T10:19:58+0000");
  script_tag(name:"last_modification", value:"2023-03-06 10:19:58 +0000 (Mon, 06 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 20:51:00 +0000 (Fri, 03 Mar 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1648-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1648-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191648-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evince' package(s) announced via the SUSE-SU-2019:1648-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for evince provides the following fixes:

Security issue fixed:
CVE-2019-11459: Fixed an improper error handling in which could have led
 to use of unitialized use of memory (bsc#1133037).

Other issue addressed:
Removed Supplements from psdocument package, so that it isn't pulled in
 by default (bsc#1122794).");

  script_tag(name:"affected", value:"'evince' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"evince", rpm:"evince~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-debuginfo", rpm:"evince-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-debugsource", rpm:"evince-debugsource~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-devel", rpm:"evince-devel~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-lang", rpm:"evince-lang~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-djvudocument", rpm:"evince-plugin-djvudocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-djvudocument-debuginfo", rpm:"evince-plugin-djvudocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-dvidocument", rpm:"evince-plugin-dvidocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-dvidocument-debuginfo", rpm:"evince-plugin-dvidocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-pdfdocument", rpm:"evince-plugin-pdfdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-pdfdocument-debuginfo", rpm:"evince-plugin-pdfdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-psdocument", rpm:"evince-plugin-psdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-psdocument-debuginfo", rpm:"evince-plugin-psdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-tiffdocument", rpm:"evince-plugin-tiffdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-tiffdocument-debuginfo", rpm:"evince-plugin-tiffdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-xpsdocument", rpm:"evince-plugin-xpsdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-xpsdocument-debuginfo", rpm:"evince-plugin-xpsdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevdocument3-4", rpm:"libevdocument3-4~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevdocument3-4-debuginfo", rpm:"libevdocument3-4-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevview3-3", rpm:"libevview3-3~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevview3-3-debuginfo", rpm:"libevview3-3-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-evince", rpm:"nautilus-evince~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-evince-debuginfo", rpm:"nautilus-evince-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EvinceDocument-3_0", rpm:"typelib-1_0-EvinceDocument-3_0~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EvinceView-3_0", rpm:"typelib-1_0-EvinceView-3_0~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"evince", rpm:"evince~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-debuginfo", rpm:"evince-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-debugsource", rpm:"evince-debugsource~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-devel", rpm:"evince-devel~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-lang", rpm:"evince-lang~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-djvudocument", rpm:"evince-plugin-djvudocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-djvudocument-debuginfo", rpm:"evince-plugin-djvudocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-dvidocument", rpm:"evince-plugin-dvidocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-dvidocument-debuginfo", rpm:"evince-plugin-dvidocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-pdfdocument", rpm:"evince-plugin-pdfdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-pdfdocument-debuginfo", rpm:"evince-plugin-pdfdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-psdocument", rpm:"evince-plugin-psdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-psdocument-debuginfo", rpm:"evince-plugin-psdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-tiffdocument", rpm:"evince-plugin-tiffdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-tiffdocument-debuginfo", rpm:"evince-plugin-tiffdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-xpsdocument", rpm:"evince-plugin-xpsdocument~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"evince-plugin-xpsdocument-debuginfo", rpm:"evince-plugin-xpsdocument-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevdocument3-4", rpm:"libevdocument3-4~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevdocument3-4-debuginfo", rpm:"libevdocument3-4-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevview3-3", rpm:"libevview3-3~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libevview3-3-debuginfo", rpm:"libevview3-3-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-evince", rpm:"nautilus-evince~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nautilus-evince-debuginfo", rpm:"nautilus-evince-debuginfo~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EvinceDocument-3_0", rpm:"typelib-1_0-EvinceDocument-3_0~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-EvinceView-3_0", rpm:"typelib-1_0-EvinceView-3_0~3.26.0+20180128.1bd86963~4.7.3", rls:"SLES15.0SP1"))) {
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
