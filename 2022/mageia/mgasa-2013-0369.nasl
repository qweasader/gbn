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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0369");
  script_cve_id("CVE-2012-6150", "CVE-2013-4408");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2013-0369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0369");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0369.html");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2012-6150");
  script_xref(name:"URL", value:"http://www.samba.org/samba/security/CVE-2013-4408");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2812");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11871");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the MGASA-2013-0369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated samba packages fix security vulnerabilities:

Samba before 3.6.22 incorrectly allows login from authenticated users if the
require_membership_of parameter of pam_winbind specifies only invalid group
names (CVE-2012-6150).

It was discovered that multiple buffer overflows in the processing of DCE-RPC
packets may lead to the execution of arbitrary code (CVE-2013-4408).");

  script_tag(name:"affected", value:"'samba' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64netapi-devel", rpm:"lib64netapi-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64netapi0", rpm:"lib64netapi0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0", rpm:"lib64smbclient0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0-devel", rpm:"lib64smbclient0-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbclient0-static-devel", rpm:"lib64smbclient0-static-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbsharemodes-devel", rpm:"lib64smbsharemodes-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64smbsharemodes0", rpm:"lib64smbsharemodes0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient-devel", rpm:"lib64wbclient-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wbclient0", rpm:"lib64wbclient0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi-devel", rpm:"libnetapi-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnetapi0", rpm:"libnetapi0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0", rpm:"libsmbclient0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-devel", rpm:"libsmbclient0-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient0-static-devel", rpm:"libsmbclient0-static-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes-devel", rpm:"libsmbsharemodes-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbsharemodes0", rpm:"libsmbsharemodes0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient-devel", rpm:"libwbclient-devel~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwbclient0", rpm:"libwbclient0~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss_wins", rpm:"nss_wins~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-server", rpm:"samba-server~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-virusfilter-clamav", rpm:"samba-virusfilter-clamav~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-virusfilter-fsecure", rpm:"samba-virusfilter-fsecure~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-virusfilter-sophos", rpm:"samba-virusfilter-sophos~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.15~1.3.mga3", rls:"MAGEIA3"))) {
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
