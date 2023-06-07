# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852449");
  script_version("2021-09-07T09:01:33+0000");
  script_cve_id("CVE-2019-6438");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-04-25 02:00:35 +0000 (Thu, 25 Apr 2019)");
  script_name("openSUSE: Security Advisory for slurm (openSUSE-SU-2019:1264-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1264-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-04/msg00090.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm'
  package(s) announced via the openSUSE-SU-2019:1264-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for slurm to version 17.11.13 fixes the following issues:

  Security issue fixed:

  - CVE-2019-6438: Fixed a heap overflow on 32-bit systems in xmalloc
  (bsc#1123304).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1264=1");

  script_tag(name:"affected", value:"'slurm' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libpmi0", rpm:"libpmi0~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpmi0-debuginfo", rpm:"libpmi0-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm32", rpm:"libslurm32~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libslurm32-debuginfo", rpm:"libslurm32-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm", rpm:"perl-slurm~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-slurm-debuginfo", rpm:"perl-slurm-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm", rpm:"slurm~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-auth-none", rpm:"slurm-auth-none~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-auth-none-debuginfo", rpm:"slurm-auth-none-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-config", rpm:"slurm-config~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debuginfo", rpm:"slurm-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-debugsource", rpm:"slurm-debugsource~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-devel", rpm:"slurm-devel~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-doc", rpm:"slurm-doc~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-lua", rpm:"slurm-lua~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-lua-debuginfo", rpm:"slurm-lua-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-munge", rpm:"slurm-munge~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-munge-debuginfo", rpm:"slurm-munge-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-node", rpm:"slurm-node~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-node-debuginfo", rpm:"slurm-node-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-openlava", rpm:"slurm-openlava~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm", rpm:"slurm-pam_slurm~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-pam_slurm-debuginfo", rpm:"slurm-pam_slurm-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-plugins", rpm:"slurm-plugins~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-plugins-debuginfo", rpm:"slurm-plugins-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-seff", rpm:"slurm-seff~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sjstat", rpm:"slurm-sjstat~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd", rpm:"slurm-slurmdbd~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-slurmdbd-debuginfo", rpm:"slurm-slurmdbd-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sql", rpm:"slurm-sql~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sql-debuginfo", rpm:"slurm-sql-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sview", rpm:"slurm-sview~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-sview-debuginfo", rpm:"slurm-sview-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque", rpm:"slurm-torque~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"slurm-torque-debuginfo", rpm:"slurm-torque-debuginfo~17.11.13~lp150.5.20.1", rls:"openSUSELeap15.0"))) {
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
