# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852145");
  script_version("2022-08-31T10:10:28+0000");
  script_cve_id("CVE-2018-0734", "CVE-2018-0735");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:41:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-11-26 15:08:57 +0100 (Mon, 26 Nov 2018)");
  script_name("openSUSE: Security Advisory for openssl-1_1 (openSUSE-SU-2018:3890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:3890-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00043.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_1'
  package(s) announced via the openSUSE-SU-2018:3890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_1 fixes the following issues:

  Security issues fixed:

  - CVE-2018-0734: timing vulnerability in DSA signature generation
  (bsc#1113652).

  - CVE-2018-0735: timing vulnerability in ECDSA signature generation
  (bsc#1113651).

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1465=1");

  script_tag(name:"affected", value:"openssl-1_1 on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel", rpm:"libopenssl-1_1-devel~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1", rpm:"libopenssl1_1~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-debuginfo", rpm:"libopenssl1_1-debuginfo~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac", rpm:"libopenssl1_1-hmac~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1", rpm:"openssl-1_1~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debuginfo", rpm:"openssl-1_1-debuginfo~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-debugsource", rpm:"openssl-1_1-debugsource~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_1-doc", rpm:"openssl-1_1-doc~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_1-devel-32bit", rpm:"libopenssl-1_1-devel-32bit~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit", rpm:"libopenssl1_1-32bit~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-32bit-debuginfo", rpm:"libopenssl1_1-32bit-debuginfo~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_1-hmac-32bit", rpm:"libopenssl1_1-hmac-32bit~1.1.0i~lp150.3.15.1", rls:"openSUSELeap15.0"))) {
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
