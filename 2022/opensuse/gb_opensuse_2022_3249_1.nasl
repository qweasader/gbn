# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.854979");
  script_version("2022-09-13T10:15:09+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-13 10:15:09 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 01:01:53 +0000 (Tue, 13 Sep 2022)");
  script_name("openSUSE: Security Advisory for clamav (SUSE-SU-2022:3249-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3249-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GDISXVLSYOTJ3GZ34DMQ6VNHKGBW2SJP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the SUSE-SU-2022:3249-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:
  clamav was updated to 0.103.7 (bsc#1202986)

  * Upgrade the vendored UnRAR library to version 6.1.7.

  * Fix logical signature 'Intermediates' feature.

  * Relax constraints on slightly malformed zip archives that contain
       overlapping file entries.");

  script_tag(name:"affected", value:"'clamav' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.7~150000.3.41.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-devel", rpm:"clamav-devel~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9", rpm:"libclamav9~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclamav9-debuginfo", rpm:"libclamav9-debuginfo~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2", rpm:"libfreshclam2~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreshclam2-debuginfo", rpm:"libfreshclam2-debuginfo~0.103.7~150000.3.41.1", rls:"openSUSELeap15.3"))) {
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