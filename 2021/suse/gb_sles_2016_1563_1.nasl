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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.1563.1");
  script_cve_id("CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-18 18:07:00 +0000 (Thu, 18 Jun 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:1563-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:1563-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20161563-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp' package(s) announced via the SUSE-SU-2016:1563-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ntp was updated to version 4.2.8p8 to fix five security issues.
These security issues were fixed:
- CVE-2016-4953: Bad authentication demobilizes ephemeral associations
 (bsc#982065).
- CVE-2016-4954: Processing spoofed server packets (bsc#982066).
- CVE-2016-4955: Autokey association reset (bsc#982067).
- CVE-2016-4956: Broadcast interleave (bsc#982068).
- CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).
These non-security issues were fixed:
- Keep the parent process alive until the daemon has finished
 initialisation, to make sure that the PID file exists when the parent
 returns.
- bsc#979302: Change the process name of the forking DNS worker process to
 avoid the impression that ntpd is started twice.
- bsc#981422: Don't ignore SIGCHILD because it breaks wait().
- bsc#979981: ntp-wait does not accept fractional seconds, so use 1
 instead of 0.2 in ntp-wait.service.
- Separate the creation of ntp.keys and key #1 in it to avoid problems
 when upgrading installations that have the file, but no key #1, which is
 needed e.g. by 'rcntp addserver'.");

  script_tag(name:"affected", value:"'ntp' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p8~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p8~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p8~14.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p8~14.1", rls:"SLES12.0SP1"))) {
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
