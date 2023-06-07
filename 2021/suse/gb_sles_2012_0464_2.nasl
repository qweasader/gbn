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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.0464.2");
  script_cve_id("CVE-2011-3970");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:0464-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:0464-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20120464-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt' package(s) announced via the SUSE-SU-2012:0464-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libxslt was prone to an out-of-bounds read flaw when parsing certain patterns (CVE-2011-3970). This could have lead to a Denial of Service and is fixed with this update.

Security Issue reference:

 * CVE-2011-3970
>");

  script_tag(name:"affected", value:"'libxslt' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxslt", rpm:"libxslt~1.1.15~15.16.21", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-32bit", rpm:"libxslt-32bit~1.1.15~15.16.21", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-64bit", rpm:"libxslt-64bit~1.1.15~15.16.21", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.15~15.16.21", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel-32bit", rpm:"libxslt-devel-32bit~1.1.15~15.16.21", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-devel-64bit", rpm:"libxslt-devel-64bit~1.1.15~15.16.21", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxslt-x86", rpm:"libxslt-x86~1.1.15~15.16.21", rls:"SLES10.0SP4"))) {
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
