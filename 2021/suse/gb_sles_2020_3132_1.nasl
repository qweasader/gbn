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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3132.1");
  script_cve_id("CVE-2020-17489");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:51 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-26 14:46:00 +0000 (Fri, 26 Mar 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3132-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3132-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203132-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-settings-daemon, gnome-shell' package(s) announced via the SUSE-SU-2020:3132-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnome-settings-daemon, gnome-shell fixes the following issues:

gnome-settings-daemon:

Add support for recent UCM related changes in ALSA and PulseAudio.
 (jsc#SLE-16518)

Don't warn when a default source or sink is missing and the PulseAudio
 daemon is restarting. (jsc#SLE-16518)

Don't warn about starting/stopping services which don't exist.
 (bsc#1172760).

gnome-shell:

Add support for recent UCM related changes in ALSA and PulseAudio.
 (jsc#SLE-16518)

CVE-2020-17489: reset auth prompt on vt switch before fade in
 loginDialog (bsc#1175155).");

  script_tag(name:"affected", value:"'gnome-settings-daemon, gnome-shell' package(s) on SUSE Linux Enterprise Module for Desktop Applications 15-SP2, SUSE Linux Enterprise Workstation Extension 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gnome-settings-daemon", rpm:"gnome-settings-daemon~3.34.2+0~4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-settings-daemon-debuginfo", rpm:"gnome-settings-daemon-debuginfo~3.34.2+0~4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-settings-daemon-debugsource", rpm:"gnome-settings-daemon-debugsource~3.34.2+0~4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-settings-daemon-devel", rpm:"gnome-settings-daemon-devel~3.34.2+0~4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-settings-daemon-lang", rpm:"gnome-settings-daemon-lang~3.34.2+0~4.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.34.5~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-debuginfo", rpm:"gnome-shell-debuginfo~3.34.5~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-debugsource", rpm:"gnome-shell-debugsource~3.34.5~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-devel", rpm:"gnome-shell-devel~3.34.5~3.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-lang", rpm:"gnome-shell-lang~3.34.5~3.13.1", rls:"SLES15.0SP2"))) {
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
