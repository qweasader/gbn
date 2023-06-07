# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122522");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353", "CVE-2009-0354", "CVE-2009-0355", "CVE-2009-0356", "CVE-2009-0357", "CVE-2009-0358");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:13 +0000 (Thu, 08 Oct 2015)");
  script_version("2022-04-05T06:57:19+0000");
  script_tag(name:"last_modification", value:"2022-04-05 06:57:19 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2009-0256)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux4|OracleLinux5)");

  script_xref(name:"Advisory-ID", value:"ELSA-2009-0256");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2009-0256.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, nss, xulrunner' package(s) announced via the ELSA-2009-0256 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"firefox:

[3.0.6-1.0.1.el5]
- Update firstrun and homepage URLs
- Added firefox-oracle-default-prefs.js/firefox-oracle-default-bookmarks.html
 and removed the corresponding Red Hat ones
- Added patch oracle-firefox-branding.patch

[3.0.6-1]
- Update to Firefox 3.0.6
- Fixed #447390 (wrong size of icons)

nss:

[3.12.2.0-4]
- exclude binary db files from change detection

[3.12.2.0-3]
- Update to NSS_3_12_2_WITH_CKBI_1_73_RTM
- Add dependency to pkgconfig to devel package (bug456849)

xulrunner:

[1.9.0.6-1.0.1.el5]
- Added xulrunner-oracle-default-prefs.js and removed
 xulrunner-redhat-default-prefs.js

[1.9.0.6-1]
- Update to 1.9.0.6");

  script_tag(name:"affected", value:"'firefox, nss, xulrunner' package(s) on Oracle Linux 4, Oracle Linux 5.");

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

if(release == "OracleLinux4") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.6~1.0.1.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.12.2.0~3.0.1.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.12.2.0~3.0.1.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.12.2.0~3.0.1.el4", rls:"OracleLinux4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.6~1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.12.2.0~4.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.12.2.0~4.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.12.2.0~4.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.12.2.0~4.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.6~1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel", rpm:"xulrunner-devel~1.9.0.6~1.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xulrunner-devel-unstable", rpm:"xulrunner-devel-unstable~1.9.0.6~1.0.1.el5", rls:"OracleLinux5"))) {
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
