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
  script_oid("1.3.6.1.4.1.25623.1.0.854106");
  script_version("2021-09-06T09:01:34+0000");
  script_cve_id("CVE-2021-3712");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-09-06 09:01:34 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-31 16:48:00 +0000 (Tue, 31 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-25 03:01:53 +0000 (Wed, 25 Aug 2021)");
  script_name("openSUSE: Security Advisory for openssl-1_0_0 (openSUSE-SU-2021:2827-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:2827-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZXNTTGRCRZBMWGGU4UK4PHVAAZAFABI2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-1_0_0'
  package(s) announced via the openSUSE-SU-2021:2827-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openssl-1_0_0 fixes the following issues:

  - CVE-2021-3712: a bug in the code for printing certificate details could
       lead to a buffer overrun that a malicious actor could exploit to crash
       the application, causing a denial-of-service attack. [bsc#1189521]");

  script_tag(name:"affected", value:"'openssl-1_0_0' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel", rpm:"libopenssl-1_0_0-devel~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10", rpm:"libopenssl10~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl10-debuginfo", rpm:"libopenssl10-debuginfo~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0", rpm:"libopenssl1_0_0~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-debuginfo", rpm:"libopenssl1_0_0-debuginfo~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac", rpm:"libopenssl1_0_0-hmac~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam", rpm:"libopenssl1_0_0-steam~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam-debuginfo", rpm:"libopenssl1_0_0-steam-debuginfo~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0", rpm:"openssl-1_0_0~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-cavs", rpm:"openssl-1_0_0-cavs~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-cavs-debuginfo", rpm:"openssl-1_0_0-cavs-debuginfo~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debuginfo", rpm:"openssl-1_0_0-debuginfo~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-debugsource", rpm:"openssl-1_0_0-debugsource~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-1_0_0-doc", rpm:"openssl-1_0_0-doc~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-1_0_0-devel-32bit", rpm:"libopenssl-1_0_0-devel-32bit~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit", rpm:"libopenssl1_0_0-32bit~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-32bit-debuginfo", rpm:"libopenssl1_0_0-32bit-debuginfo~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-hmac-32bit", rpm:"libopenssl1_0_0-hmac-32bit~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam-32bit", rpm:"libopenssl1_0_0-steam-32bit~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl1_0_0-steam-32bit-debuginfo", rpm:"libopenssl1_0_0-steam-32bit-debuginfo~1.0.2p~3.40.2", rls:"openSUSELeap15.3"))) {
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