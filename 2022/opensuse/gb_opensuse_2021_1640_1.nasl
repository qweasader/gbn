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
  script_oid("1.3.6.1.4.1.25623.1.0.854477");
  script_version("2022-02-22T14:03:32+0000");
  script_cve_id("CVE-2021-44847");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-22 14:03:32 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 15:39:00 +0000 (Thu, 16 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-02-08 08:17:12 +0000 (Tue, 08 Feb 2022)");
  script_name("openSUSE: Security Advisory for c-toxcore (openSUSE-SU-2021:1640-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1640-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MUGBIA3IOPBRCHCVWXL5KMYQ6TB5Z5XI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'c-toxcore'
  package(s) announced via the openSUSE-SU-2021:1640-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"c-toxcore was updated for fix a security issue:

  - CVE-2021-44847: Fixed a buffer overflow in handle_request in DHT.c which
       could lead to remote DoS and potential code execution (boo#1193667)");

  script_tag(name:"affected", value:"'c-toxcore' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"c-toxcore", rpm:"c-toxcore~0.2.13~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-toxcore-daemon", rpm:"c-toxcore-daemon~0.2.13~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-toxcore-daemon-debuginfo", rpm:"c-toxcore-daemon-debuginfo~0.2.13~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-toxcore-debuginfo", rpm:"c-toxcore-debuginfo~0.2.13~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"c-toxcore-devel", rpm:"c-toxcore-devel~0.2.13~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtoxcore2", rpm:"libtoxcore2~0.2.13~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtoxcore2-debuginfo", rpm:"libtoxcore2-debuginfo~0.2.13~lp152.3.3.1", rls:"openSUSELeap15.2"))) {
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
