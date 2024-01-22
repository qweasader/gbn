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
  script_oid("1.3.6.1.4.1.25623.1.0.853724");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-35459", "CVE-2021-3020");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-02 13:29:00 +0000 (Fri, 02 Sep 2022)");
  script_tag(name:"creation_date", value:"2021-04-16 05:01:43 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for crmsh (openSUSE-SU-2021:0410-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0410-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BNDVFBI7G272LNZ2QQZ4MY56KX2J4C36");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'crmsh'
  package(s) announced via the openSUSE-SU-2021:0410-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for crmsh fixes the following issues:

  - Update to version 4.3.0+20210305.9db5c9a8:

  * Fix: bootstrap: Adjust qdevice configure/remove process to avoid race
         condition due to quorum lost(bsc#1181415)

  * Dev: cibconfig: remove related code about detecting crm_diff support

  - -no-verion

  * Fix: ui_configure: raise error when params not exist(bsc#1180126)

  * Dev: doc: remove doc for crm node status

  * Dev: ui_node: remove status subcommand

  - Update to version 4.3.0+20210219.5d1bf034:

  * Fix: hb_report: walk through hb_report process under
         hacluster(CVE-2020-35459, bsc#1179999  CVE-2021-3020, bsc#1180571)

  * Fix: bootstrap: setup authorized ssh access for
         hacluster(CVE-2020-35459, bsc#1179999  CVE-2021-3020, bsc#1180571)

  * Dev: analyze: Add analyze sublevel and put preflight_check in
         it(jsc#ECO-1658)

  * Dev: utils: change default file mod as 644 for str2file function

  * Dev: hb_report: Detect if any ocfs2 partitions exist

  * Dev: lock: give more specific error message when raise ClaimLockError

  * Fix: Replace mktemp() to mkstemp() for security

  * Fix: Remove the duplicate --cov-report html in tox.

  * Fix: fix some lint issues.

  * Fix: Replace utils.msg_info to task.info

  * Fix: Solve a circular import error of utils.py

  * Fix: hb_report: run lsof with specific ocfs2 device(bsc#1180688)

  * Dev: corosync: change the permission of corosync.conf to 644

  * Fix: preflight_check: task: raise error when report_path isn&#x27 t a
         directory

  * Fix: bootstrap: Use class Watchdog to simplify watchdog
         config(bsc#1154927, bsc#1178869)

  * Dev: Polish the sbd feature.

  * Dev: Replace -f with -c and run check when no parameter provide.

  * Fix: Fix the yes option not working

  * Fix: Remove useless import and show help when no input.

  * Dev: Correct SBD device id inconsistenc during ASR

  * Fix: completers: return complete start/stop resource id list
         correctly(bsc#1180137)

  * Dev: Makefile.am: change makefile to integrate preflight_check

  * Medium: integrate preflight_check into crmsh(jsc#ECO-1658)

  * Fix: bootstrap: make sure sbd device UUID was the same between
         nodes(bsc#1178454)

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'crmsh' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"crmsh", rpm:"crmsh~4.3.0+20210305.9db5c9a8~lp152.4.47.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crmsh-scripts", rpm:"crmsh-scripts~4.3.0+20210305.9db5c9a8~lp152.4.47.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"crmsh-test", rpm:"crmsh-test~4.3.0+20210305.9db5c9a8~lp152.4.47.1", rls:"openSUSELeap15.2"))) {
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