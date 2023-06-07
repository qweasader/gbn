# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122354");
  script_cve_id("CVE-2008-5302", "CVE-2008-5303", "CVE-2010-1168", "CVE-2010-1447");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:24 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T07:50:33+0000");
  script_tag(name:"last_modification", value:"2022-04-05 07:50:33 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2010-0458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0458");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0458.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the ELSA-2010-0458 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4:5.8.8-32.el5.1]
- third version of patch fix change of behaviour of rmtree for common user
- Resolves: rhbz#597203

[4:5.8.8-32.el5]
- rhbz#595416 change documentation of File::Path
- Related: rhbz#591167

[4:5.8.8-31.el5]
- remove previous fix
- Related: rhbz#591167

[4:5.8.8-30.el5]
- change config to file on Util.so
- Related: rhbz#594406

[4:5.8.8-29.el5]
- CVE-2008-5302 - use latest patch without Cwd module
- 507378 because of our paths we need to overload old Util.so in case customer installed
 Scalar::Util from cpan. In this case we marked new Util.so as .rpmnew.
- Related: rhbz#591167
- Resolves: rhbz#594406

[4:5.8.8-28.el5]
- CVE-2008-5302 perl: File::Path rmtree race condition (CVE-2005-0448)
 reintroduced after upstream rebase to 5.8.8-1
- CVE-2010-1168 perl Safe: Intended restriction bypass via object references
- CVE-2010-1447 Safe 2.26 and earlier: Intended restriction bypass via Perl
 object references in code executed outside safe compartment
- Related: rhbz#591167");

  script_tag(name:"affected", value:"'perl' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.8.8~32.el5_5.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.8.8~32.el5_5.1", rls:"OracleLinux5"))) {
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
