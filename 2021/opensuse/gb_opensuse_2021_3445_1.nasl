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
  script_oid("1.3.6.1.4.1.25623.1.0.854219");
  script_version("2022-09-20T10:11:40+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"creation_date", value:"2021-10-16 01:07:15 +0000 (Sat, 16 Oct 2021)");
  script_name("openSUSE: Security Advisory for rpm (openSUSE-SU-2021:3445-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3445-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GAZ7Q6SIGPUY3S4AEODOSAFRBJHEPSOM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rpm'
  package(s) announced via the openSUSE-SU-2021:3445-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rpm fixes the following issues:

     Security issues fixed:

  - PGP hardening changes (bsc#1185299)

     Maintenance issues fixed:

  - Fixed zstd detection (bsc#1187670)

  - Added ndb rofs support (bsc#1188548)

  - Fixed deadlock when multiple rpm processes try tp acquire the database
       lock (bsc#1183659)");

  script_tag(name:"affected", value:"'rpm' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"python-rpm-debugsource", rpm:"python-rpm-debugsource~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rpm", rpm:"python2-rpm~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-rpm-debuginfo", rpm:"python2-rpm-debuginfo~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm", rpm:"python3-rpm~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rpm-debuginfo", rpm:"python3-rpm-debuginfo~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm", rpm:"rpm~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build", rpm:"rpm-build~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-build-debuginfo", rpm:"rpm-build-debuginfo~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-debuginfo", rpm:"rpm-debuginfo~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-debugsource", rpm:"rpm-debugsource~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-devel", rpm:"rpm-devel~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-ndb", rpm:"rpm-ndb~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-ndb-debuginfo", rpm:"rpm-ndb-debuginfo~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-ndb-debugsource", rpm:"rpm-ndb-debugsource~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-32bit", rpm:"rpm-32bit~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-32bit-debuginfo", rpm:"rpm-32bit-debuginfo~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-ndb-32bit", rpm:"rpm-ndb-32bit~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rpm-ndb-32bit-debuginfo", rpm:"rpm-ndb-32bit-debuginfo~4.14.3~40.1", rls:"openSUSELeap15.3"))) {
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