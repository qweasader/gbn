# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853429");
  script_version("2021-08-12T14:00:53+0000");
  script_cve_id("CVE-2020-12693", "CVE-2020-1269");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-08-12 14:00:53 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-19 18:15:00 +0000 (Sat, 19 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-14 03:00:47 +0000 (Mon, 14 Sep 2020)");
  script_name("openSUSE: Security Advisory for slurm (openSUSE-SU-2020:1421-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1421-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-09/msg00035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm'
  package(s) announced via the openSUSE-SU-2020:1421-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm fixes the following issues:

  - Fix Authentication Bypass when Message Aggregation is enabled
  CVE-2020-12693 This fixes and issue where authentication could be
  bypassed via an alternate path or channel when message Aggregation was
  enabled. A race condition allowed a user to launch a process as an
  arbitrary user. Add:
  Fix-Authentication-Bypass-when-Message-Aggregation-is-enabled-CVE-2020-1269
  3.patch (CVE-2020-12693, bsc#1172004).

  - Remove unneeded build dependency to postgresql-devel.

  This update was imported from the SUSE:SLE-15-SP1:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1421=1");

  script_tag(name:"affected", value:"'slurm' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"libpmi0", rpm:"libpmi0~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0-debuginfo", rpm:"libpmi0-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm33", rpm:"libslurm33~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm33-debuginfo", rpm:"libslurm33-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm", rpm:"perl-slurm~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm-debuginfo", rpm:"perl-slurm-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm", rpm:"slurm~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-auth-none", rpm:"slurm-auth-none~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-auth-none-debuginfo", rpm:"slurm-auth-none-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-config", rpm:"slurm-config~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-config-man", rpm:"slurm-config-man~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-cray", rpm:"slurm-cray~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-cray-debuginfo", rpm:"slurm-cray-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debuginfo", rpm:"slurm-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debugsource", rpm:"slurm-debugsource~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-devel", rpm:"slurm-devel~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-doc", rpm:"slurm-doc~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-hdf5", rpm:"slurm-hdf5~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-hdf5-debuginfo", rpm:"slurm-hdf5-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-lua", rpm:"slurm-lua~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-lua-debuginfo", rpm:"slurm-lua-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-munge", rpm:"slurm-munge~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-munge-debuginfo", rpm:"slurm-munge-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-node", rpm:"slurm-node~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-node-debuginfo", rpm:"slurm-node-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-openlava", rpm:"slurm-openlava~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm", rpm:"slurm-pam_slurm~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm-debuginfo", rpm:"slurm-pam_slurm-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-plugins", rpm:"slurm-plugins~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-plugins-debuginfo", rpm:"slurm-plugins-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-seff", rpm:"slurm-seff~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sjstat", rpm:"slurm-sjstat~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd", rpm:"slurm-slurmdbd~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd-debuginfo", rpm:"slurm-slurmdbd-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sql", rpm:"slurm-sql~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sql-debuginfo", rpm:"slurm-sql-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sview", rpm:"slurm-sview~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sview-debuginfo", rpm:"slurm-sview-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque", rpm:"slurm-torque~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque-debuginfo", rpm:"slurm-torque-debuginfo~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-webdoc", rpm:"slurm-webdoc~18.08.9~lp151.2.10.1", rls:"openSUSELeap15.1"))) {
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