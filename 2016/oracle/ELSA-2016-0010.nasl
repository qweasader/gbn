# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.122818");
  script_cve_id("CVE-2015-3223", "CVE-2015-5252", "CVE-2015-5296", "CVE-2015-5299", "CVE-2015-7540");
  script_tag(name:"creation_date", value:"2016-01-08 05:47:22 +0000 (Fri, 08 Jan 2016)");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:44:00 +0000 (Mon, 29 Aug 2022)");

  script_name("Oracle: Security Advisory (ELSA-2016-0010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0010");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0010.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba4' package(s) announced via the ELSA-2016-0010 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4.0.0-67.rc4]
- resolves: #1290708 - CVE-2015-7540
- related: #1290708 - CVE-2015-5299
- related: #1290708 - CVE-2015-5296
- related: #1290708 - CVE-2015-5252
- related: #1290708 - CVE-2015-5330");

  script_tag(name:"affected", value:"'samba4' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"samba4", rpm:"samba4~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-client", rpm:"samba4-client~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-common", rpm:"samba4-common~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-dc", rpm:"samba4-dc~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-dc-libs", rpm:"samba4-dc-libs~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-devel", rpm:"samba4-devel~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-libs", rpm:"samba4-libs~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-pidl", rpm:"samba4-pidl~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-python", rpm:"samba4-python~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-swat", rpm:"samba4-swat~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-test", rpm:"samba4-test~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-winbind", rpm:"samba4-winbind~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-winbind-clients", rpm:"samba4-winbind-clients~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba4-winbind-krb5-locator", rpm:"samba4-winbind-krb5-locator~4.0.0~67.el6_7.rc4", rls:"OracleLinux6"))) {
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
