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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0573.1");
  script_cve_id("CVE-2016-9962", "CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-01 20:15:00 +0000 (Thu, 01 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0573-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190573-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, docker, docker-runc, golang-github-docker-libnetwork, runc' package(s) announced via the SUSE-SU-2019:0573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork, runc fixes the following issues:

Security issues fixed:
CVE-2018-16875: Fixed a CPU Denial of Service (bsc#1118899).

CVE-2018-16874: Fixed a vulnerabity in go get command which could allow
 directory traversal in GOPATH mode (bsc#1118898).

CVE-2018-16873: Fixed a vulnerability in go get command which could
 allow remote code execution when executed with -u in GOPATH mode
 (bsc#1118897).

CVE-2019-5736: Effectively copying /proc/self/exe during re-exec to
 avoid write attacks to the host runc binary, which could lead to a
 container breakout (bsc#1121967).

Other changes and bug fixes:
Update shell completion to use Group: System/Shells.

Add daemon.json file with rotation logs configuration (bsc#1114832)

Update to Docker 18.09.1-ce (bsc#1124308) and to runc 96ec2177ae84.
 See upstream changelog in the packaged
 /usr/share/doc/packages/docker/CHANGELOG.md.

Disable leap based builds for kubic flavor (bsc#1121412).

Allow users to explicitly specify the NIS domain name of a container
 (bsc#1001161).

Update docker.service to match upstream and avoid rlimit problems
 (bsc#1112980).

Update go requirements to >= go1.10

Use -buildmode=pie for tests and binary build (bsc#1048046 and
 bsc#1051429).

Remove the usage of 'cp -r' to reduce noise in the build logs.");

  script_tag(name:"affected", value:"'containerd, docker, docker-runc, golang-github-docker-libnetwork, runc' package(s) on SUSE Linux Enterprise Module for Containers 12, SUSE OpenStack Cloud 6.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.2.2~16.14.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~18.09.1_ce~98.34.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~18.09.1_ce~98.34.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debugsource", rpm:"docker-debugsource~18.09.1_ce~98.34.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2711_2cfbf9b1f981~16.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2711_2cfbf9b1f981~16.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc6+gitr3748_96ec2177ae84~1.17.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker-libnetwork-debugsource", rpm:"golang-github-docker-libnetwork-debugsource~0.7.0.1+gitr2711_2cfbf9b1f981~16.2", rls:"SLES12.0"))) {
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
