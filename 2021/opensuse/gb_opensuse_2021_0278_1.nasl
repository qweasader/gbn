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
  script_oid("1.3.6.1.4.1.25623.1.0.853705");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-15257", "CVE-2021-21284", "CVE-2021-21285");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-10 05:15:00 +0000 (Sat, 10 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:00:53 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for containerd, (openSUSE-SU-2021:0278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0278-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/UGKTLORCQ4MPZPDFGWKJEEPQRXFUTZYZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'containerd, '
  package(s) announced via the openSUSE-SU-2021:0278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for containerd, docker, docker-runc,
     golang-github-docker-libnetwork fixes the following issues:

     Security issues fixed:

  - CVE-2020-15257: Fixed a privilege escalation in containerd (bsc#1178969).

  - CVE-2021-21284: potential privilege escalation when the root user in the
       remapped namespace has access to the host filesystem (bsc#1181732)

  - CVE-2021-21285: pulling a malformed Docker image manifest crashes the
       dockerd daemon (bsc#1181730)

     Non-security issues fixed:

  - Update Docker to 19.03.15-ce. See upstream changelog in the packaged
       /usr/share/doc/packages/docker/CHANGELOG.md. This update includes fixes
       for bsc#1181732 (CVE-2021-21284) and bsc#1181730 (CVE-2021-21285).

  - Only apply the boo#1178801 libnetwork patch to handle firewalld on
       openSUSE. It appears that SLES doesn&#x27 t like the patch. (bsc#1180401)

  - Update to containerd v1.3.9, which is needed for Docker v19.03.14-ce and
       fixes CVE-2020-15257. bsc#1180243

  - Update to containerd v1.3.7, which is required for Docker 19.03.13-ce.
       bsc#1176708

  - Update to Docker 19.03.14-ce. See upstream changelog in the packaged
       /usr/share/doc/packages/docker/CHANGELOG.md. CVE-2020-15257 bsc#1180243

  - Enable fish-completion

  - Add a patch which makes Docker compatible with firewalld with nftables
  backend.
       (bsc#1178801, SLE-16460)

  - Update to Docker 19.03.13-ce. See upstream changelog in the packaged
       /usr/share/doc/packages/docker/CHANGELOG.md. bsc#1176708

  - Fixes for %_libexecdir changing to /usr/libexec (bsc#1174075)

  - Emergency fix: %requires_eq does not work with provide symbols,
       only effective package names. Convert back to regular Requires.

  - Update to Docker 19.03.12-ce. See upstream changelog in the packaged
       /usr/share/doc/packages/docker/CHANGELOG.md.

  - Use Go 1.13 instead of Go 1.14 because Go 1.14 can cause all sorts of
       spurious errors due to Go returning -EINTR from I/O syscalls much more
       often (due to Go 1.14&#x27 s pre-emptive goroutine support).

  - Add BuildRequires for all -git dependencies so that we catch missing
       dependencies much more quickly.

  - Update to libnetwork 55e924b8a842, which is required for Docker
       19.03.14-ce.  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'containerd, ' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"containerd", rpm:"containerd~1.3.9~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"containerd-ctr", rpm:"containerd-ctr~1.3.9~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~19.03.15_ce~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-debuginfo", rpm:"docker-debuginfo~19.03.15_ce~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork", rpm:"docker-libnetwork~0.7.0.1+gitr2908_55e924b8a842~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-libnetwork-debuginfo", rpm:"docker-libnetwork-debuginfo~0.7.0.1+gitr2908_55e924b8a842~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc", rpm:"docker-runc~1.0.0rc10+gitr3981_dc9208a3303f~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-runc-debuginfo", rpm:"docker-runc-debuginfo~1.0.0rc10+gitr3981_dc9208a3303f~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test", rpm:"docker-test~19.03.15_ce~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-test-debuginfo", rpm:"docker-test-debuginfo~19.03.15_ce~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fish", rpm:"fish~2.7.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fish-debuginfo", rpm:"fish-debuginfo~2.7.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fish-debugsource", rpm:"fish-debugsource~2.7.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fish-devel", rpm:"fish-devel~2.7.1~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-github-docker-libnetwork", rpm:"golang-github-docker-libnetwork~0.7.0.1+gitr2908_55e924b8a842~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-bash-completion", rpm:"docker-bash-completion~19.03.15_ce~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~19.03.15_ce~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~19.03.15_ce~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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
