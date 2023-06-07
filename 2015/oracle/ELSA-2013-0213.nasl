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
  script_oid("1.3.6.1.4.1.25623.1.0.123738");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:54 +0000 (Tue, 06 Oct 2015)");
  script_version("2020-08-04T08:27:56+0000");
  script_tag(name:"last_modification", value:"2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-11 11:33:45 +0000 (Tue, 11 Jan 2022)");

  script_name("Oracle: Security Advisory (ELSA-2013-0213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0213");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0213.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss, nss-util' package(s) announced via the ELSA-2013-0213 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nspr
[4.9.2-0.1]
- Retagging to ensure n-v-r is lower than the one for rhel-6.4
- Resolves: rhbz#891661 - [RFE] Rebase nspr to 4.9.2 due to Firefox 17 ESR

[4.9.2-1]
- Resolves: rhbz#891661 - [RFE] Rebase nspr to 4.9.2 due to Firefox 17 ESR

nss
[3.13.6-2.0.1.el6_3]
- Added nss-vendor.patch to change vendor

[3.13.6-2]
- Retagging for rhel-6.3 z-stream
- Update to NSS_3_13_6_RTM
- Resolves: rhbz#891663 - Update to 3.13.5 for mozilla 10.0.6
- Resolves: rhbz#891151 [CVE-2013-0743]

[3.13.6-1]
- Update to NSS_3_13_6_RTM
- Resolves: rhbz#891663 - Update to 3.13.5 for mozilla 10.0.6
- Resolves: rhbz#891151 [CVE-2013-0743]

nss-util
[3.13.6-1]
- Update to NSS_3_13_6_RTM
- Resolves: rhbz#891670 - [RFE] Rebase to NSS-UTIL >= 3.13.6

[3.13.5-1]
- Resolves: rhbz#833763 - Update to 3.13.5 for Mozilla 10.0.6");

  script_tag(name:"affected", value:"'nspr, nss, nss-util' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9.2~0.el6_3.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9.2~0.el6_3.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.13.6~2.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.13.6~2.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.13.6~2.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-sysinit", rpm:"nss-sysinit~3.13.6~2.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.13.6~2.0.1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util", rpm:"nss-util~3.13.6~1.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-util-devel", rpm:"nss-util-devel~3.13.6~1.el6_3", rls:"OracleLinux6"))) {
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
