# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.131192");
  script_cve_id("CVE-2015-8607");
  script_tag(name:"creation_date", value:"2016-01-21 05:32:04 +0000 (Thu, 21 Jan 2016)");
  script_version("2022-06-27T10:12:27+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-15 03:15:00 +0000 (Wed, 15 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2016-0027)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0027");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0027.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17475");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3441");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2016-January/175494.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl, perl-PathTools' package(s) announced via the MGASA-2016-0027 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that File::Spec::canonpath() routine returns untainted strings
even if passed tainted input. This defect undermines the guarantee of taint
propagation, which is sometimes used to ensure that unvalidated user input does
not reach sensitive code (CVE-2015-8607).");

  script_tag(name:"affected", value:"'perl, perl-PathTools' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.20.1~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-PathTools", rpm:"perl-PathTools~3.470.0~7.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-base", rpm:"perl-base~5.20.1~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.20.1~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-doc", rpm:"perl-doc~5.20.1~8.1.mga5", rls:"MAGEIA5"))) {
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
