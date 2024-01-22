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
  script_oid("1.3.6.1.4.1.25623.1.0.852679");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2018-10892", "CVE-2019-13509", "CVE-2019-14271", "CVE-2019-5736");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 17:03:00 +0000 (Mon, 18 Apr 2022)");
  script_tag(name:"creation_date", value:"2019-08-30 02:00:50 +0000 (Fri, 30 Aug 2019)");
  script_name("openSUSE: Security Advisory for containerd, docker, docker-runc, go, go1.11, go1.12, golang-github-docker-libnetwork (openSUSE-SU-2019:2021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:2021-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-08/msg00084.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker, docker-runc,
  go, go1.11, go1.12, golang-github-docker-libnetwork' package(s) announced via the openSUSE-SU-2019:2021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc,
  golang-github-docker-libnetwork fixes the following issues:

  Docker:

  - CVE-2019-14271: Fixed a code injection if the nsswitch facility
  dynamically loaded a library inside a chroot (bsc#1143409).

  - CVE-2019-13509: Fixed an information leak in the debug log (bsc#1142160).

  - Update to version 19.03.1-ce, see changelog at
  /usr/share/doc/packages/docker/CHANGELOG.md (bsc#1142413, bsc#1139649).

  runc:

  - Use %config(noreplace) for /etc/docker/daemon.json (bsc#1138920).

  - Update to runc 425e105d5a03, which is required by Docker (bsc#1139649).

  containerd:

  - CVE-2019-5736: Fixed a container breakout vulnerability (bsc#1121967).

  - Update to containerd v1.2.6, which is required by docker (bsc#1139649).

  golang-github-docker-libnetwork:

  - Update to version git.fc5a7d91d54cc98f64fc28f9e288b46a0bee756c, which is
  required by docker (bsc#1142413, bsc#1139649).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2021=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2021=1");

  script_tag(name:"affected", value:"'containerd, ' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.2.6~lp150.4.17.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.2.6~lp150.4.17.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~19.03.1_ce~lp150.5.27.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~19.03.1_ce~lp150.5.27.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2800_fc5a7d91d54c~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2800_fc5a7d91d54c~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc8+gitr3826_425e105d5a03~lp150.5.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc8+gitr3826_425e105d5a03~lp150.5.25.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test", rpm:"docker-test~19.03.1_ce~lp150.5.27.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test-debuginfo", rpm:"docker-test-debuginfo~19.03.1_ce~lp150.5.27.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker-libnetwork", rpm:"golang-github-docker-libnetwork~0.7.0.1+gitr2800_fc5a7d91d54c~lp150.3.18.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~19.03.1_ce~lp150.5.27.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~19.03.1_ce~lp150.5.27.1", rls:"openSUSELeap15.0"))) {
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
