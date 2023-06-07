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
  script_oid("1.3.6.1.4.1.25623.1.0.854544");
  script_version("2022-09-08T10:11:29+0000");
  script_cve_id("CVE-2021-30498", "CVE-2021-30499");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-08 10:11:29 +0000 (Thu, 08 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-15 15:45:00 +0000 (Fri, 15 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 08:27:39 +0000 (Wed, 23 Mar 2022)");
  script_name("openSUSE: Security Advisory for libcaca (openSUSE-SU-2022:0769-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0769-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SRWTKUG6M4N5W7U2DBAJ4MTXKVSEHRXW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcaca'
  package(s) announced via the openSUSE-SU-2022:0769-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libcaca fixes the following issues:

  - CVE-2021-30498, CVE-2021-30499: If an image has a size of 0x0, when
       exporting, no data is written and space is allocated for the header
       only, not taking into account that sprintf appends a NUL byte
       (bsc#1184751, bsc#1184752).");

  script_tag(name:"affected", value:"'libcaca' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caca-utils-debuginfo", rpm:"caca-utils-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-debugsource", rpm:"libcaca-debugsource~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-ruby", rpm:"libcaca-ruby~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-ruby-debuginfo", rpm:"libcaca-ruby-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0", rpm:"libcaca0~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-debuginfo", rpm:"libcaca0-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins", rpm:"libcaca0-plugins~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-debuginfo", rpm:"libcaca0-plugins-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-32bit", rpm:"libcaca0-32bit~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-32bit-debuginfo", rpm:"libcaca0-32bit-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-32bit", rpm:"libcaca0-plugins-32bit~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-32bit-debuginfo", rpm:"libcaca0-plugins-32bit-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-caca", rpm:"python3-caca~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caca-utils-debuginfo", rpm:"caca-utils-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-debugsource", rpm:"libcaca-debugsource~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-ruby", rpm:"libcaca-ruby~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-ruby-debuginfo", rpm:"libcaca-ruby-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0", rpm:"libcaca0~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-debuginfo", rpm:"libcaca0-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins", rpm:"libcaca0-plugins~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-debuginfo", rpm:"libcaca0-plugins-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-32bit", rpm:"libcaca0-32bit~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-32bit-debuginfo", rpm:"libcaca0-32bit-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-32bit", rpm:"libcaca0-plugins-32bit~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0-plugins-32bit-debuginfo", rpm:"libcaca0-plugins-32bit-debuginfo~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-caca", rpm:"python3-caca~0.99.beta19.git20171003~11.3.1", rls:"openSUSELeap15.3"))) {
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