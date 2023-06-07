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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1347.1");
  script_cve_id("CVE-2017-7470");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:56 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1347-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3|SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1347-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171347-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SUSE Manager Client Tools' package(s) announced via the SUSE-SU-2017:1347-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following security issue in spacewalk-backend has been fixed:
- Non admin or disabled user cannot make changes to a system anymore using
 spacewalk-channel. (bsc#1026633, CVE-2017-7470)
Additionally, the following non-security issues have been fixed:
rhnlib:
- Support all TLS versions in rpclib. (bsc#1025312)
spacecmd:
- Improve output on error for listrepo. (bsc#1027426)
- Reword spacecmd removal message. (bsc#1024406)
spacewalk-backend:
- Do not fail with traceback when media.1 does not exist. (bsc#1032256)
- Create scap files directory beforehand. (bsc#1029755)
- Fix error if SPACEWALK_DEBUG_NO_REPORTS environment variable is not
 present.
- Don't skip 'rhnErrataPackage' cleanup during an errata update.
 (bsc#1023233)
- Add support for running spacewalk-debug without creating reports.
 (bsc#1024714)
- Set scap store directory mod to 775 and group owner to susemanager.
- incomplete_package_import: Do import rhnPackageFile as it breaks some
 package installations.
- Added traceback printing to the exception block.
- Change postgresql starting commands.
spacewalk-client-tools:
- Fix reboot message to use correct product name. (bsc#1031667)");

  script_tag(name:"affected", value:"'SUSE Manager Client Tools' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"rhnlib", rpm:"rhnlib~2.5.84.4~8.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~2.5.5.5~14.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-backend-libs", rpm:"spacewalk-backend-libs~2.5.24.9~24.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~2.5.13.8~23.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~2.5.13.8~23.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~2.5.13.8~23.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"rhnlib", rpm:"rhnlib~2.5.84.4~8.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacecmd", rpm:"spacecmd~2.5.5.5~14.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-backend-libs", rpm:"spacewalk-backend-libs~2.5.24.9~24.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-check", rpm:"spacewalk-check~2.5.13.8~23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-setup", rpm:"spacewalk-client-setup~2.5.13.8~23.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"spacewalk-client-tools", rpm:"spacewalk-client-tools~2.5.13.8~23.1", rls:"SLES11.0SP4"))) {
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
