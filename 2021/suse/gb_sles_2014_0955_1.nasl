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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0955.1");
  script_cve_id("CVE-2014-4607");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-14 15:26:00 +0000 (Fri, 14 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0955-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP3|SLES10\.0SP4|SLES11\.0SP1|SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0955-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140955-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lzo' package(s) announced via the SUSE-SU-2014:0955-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"lzo has been updated to fix a potential denial of service issue or possible remote code execution by allowing an attacker, if the LZO decompression algorithm is used in a threaded or kernel context, to corrupt memory structures that control the flow of execution in other contexts. (CVE-2014-4607)

Security Issues:

 * CVE-2014-4607");

  script_tag(name:"affected", value:"'lzo' package(s) on SUSE Linux Enterprise Server 10-SP3, SUSE Linux Enterprise Server 10-SP4, SUSE Linux Enterprise Server 11-SP1, SUSE Linux Enterprise Server 11-SP2.");

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

if(release == "SLES10.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"lzo", rpm:"lzo~2.02~12.10.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lzo-32bit", rpm:"lzo-32bit~2.02~12.10.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lzo-devel", rpm:"lzo-devel~2.02~12.10.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lzo-devel-32bit", rpm:"lzo-devel-32bit~2.02~12.10.1", rls:"SLES10.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"lzo", rpm:"lzo~2.02~12.10.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lzo-32bit", rpm:"lzo-32bit~2.02~12.10.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lzo-devel", rpm:"lzo-devel~2.02~12.10.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lzo-devel-32bit", rpm:"lzo-devel-32bit~2.02~12.10.1", rls:"SLES10.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"liblzo2-2", rpm:"liblzo2-2~2.03~12.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzo2-2-32bit", rpm:"liblzo2-2-32bit~2.03~12.3.1", rls:"SLES11.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"liblzo2-2", rpm:"liblzo2-2~2.03~12.3.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liblzo2-2-32bit", rpm:"liblzo2-2-32bit~2.03~12.3.1", rls:"SLES11.0SP2"))) {
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
