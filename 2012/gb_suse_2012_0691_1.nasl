# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850195");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2012-12-13 17:02:00 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-2388");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:0691-1");
  script_name("openSUSE: Security Advisory for update (openSUSE-SU-2012:0691-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'update'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE12\.1)");

  script_tag(name:"affected", value:"update on openSUSE 12.1, openSUSE 11.4");

  script_tag(name:"insight", value:"Strongswan's gmp plugin could treat empty RSA signature as
  valid ones");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev1", rpm:"strongswan-ikev1~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev1-debuginfo", rpm:"strongswan-ikev1-debuginfo~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev2", rpm:"strongswan-ikev2~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev2-debuginfo", rpm:"strongswan-ikev2-debuginfo~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-mysql", rpm:"strongswan-mysql~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-mysql-debuginfo", rpm:"strongswan-mysql-debuginfo~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm", rpm:"strongswan-nm~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm-debuginfo", rpm:"strongswan-nm-debuginfo~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite", rpm:"strongswan-sqlite~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite-debuginfo", rpm:"strongswan-sqlite-debuginfo~4.5.0~6.45.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev1", rpm:"strongswan-ikev1~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev1-debuginfo", rpm:"strongswan-ikev1-debuginfo~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev2", rpm:"strongswan-ikev2~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ikev2-debuginfo", rpm:"strongswan-ikev2-debuginfo~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-mysql", rpm:"strongswan-mysql~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-mysql-debuginfo", rpm:"strongswan-mysql-debuginfo~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm", rpm:"strongswan-nm~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm-debuginfo", rpm:"strongswan-nm-debuginfo~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite", rpm:"strongswan-sqlite~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite-debuginfo", rpm:"strongswan-sqlite-debuginfo~4.5.3~5.4.1", rls:"openSUSE12.1"))) {
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