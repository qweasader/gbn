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
  script_oid("1.3.6.1.4.1.25623.1.0.822498");
  script_version("2022-09-23T10:10:45+0000");
  script_cve_id("CVE-2019-13224", "CVE-2019-16163", "CVE-2019-19203", "CVE-2019-19204", "CVE-2019-19246", "CVE-2020-26159");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-23 10:10:45 +0000 (Fri, 23 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:33:00 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-09-22 01:02:27 +0000 (Thu, 22 Sep 2022)");
  script_name("openSUSE: Security Advisory for oniguruma (SUSE-SU-2022:3327-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3327-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/CEWPX42Q7UUAW2DIUKSQQW5EWUH5JC36");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oniguruma'
  package(s) announced via the SUSE-SU-2022:3327-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for oniguruma fixes the following issues:

  - CVE-2019-19246: Fixed an out of bounds access during regular expression
       matching (bsc#1157805).

  - CVE-2019-19204: Fixed an out of bounds access when compiling a crafted
       regular expression (bsc#1164569).

  - CVE-2019-19203: Fixed an out of bounds access when performing a string
       search (bsc#1164550).

  - CVE-2019-16163: Fixed an uncontrolled recursion issue when compiling a
       crafted regular expression, which could lead to denial of service
       (bsc#1150130).

  - CVE-2020-26159: Fixed an off-by-one buffer overflow (bsc#1177179).

  - CVE-2019-13224: Fixed a potential use-after-free when handling multiple
       different encodings (bsc#1142847).");

  script_tag(name:"affected", value:"'oniguruma' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libonig4", rpm:"libonig4~6.7.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libonig4-debuginfo", rpm:"libonig4-debuginfo~6.7.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-debugsource", rpm:"oniguruma-debugsource~6.7.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-devel", rpm:"oniguruma-devel~6.7.0~150000.3.3.1", rls:"openSUSELeap15.4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libonig4", rpm:"libonig4~6.7.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libonig4-debuginfo", rpm:"libonig4-debuginfo~6.7.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-debugsource", rpm:"oniguruma-debugsource~6.7.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oniguruma-devel", rpm:"oniguruma-devel~6.7.0~150000.3.3.1", rls:"openSUSELeap15.3"))) {
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
