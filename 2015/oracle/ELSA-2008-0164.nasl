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
  script_oid("1.3.6.1.4.1.25623.1.0.122602");
  script_cve_id("CVE-2007-5901", "CVE-2007-5971", "CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947");
  script_tag(name:"creation_date", value:"2015-10-08 11:49:02 +0000 (Thu, 08 Oct 2015)");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:34:00 +0000 (Thu, 28 Dec 2023)");

  script_name("Oracle: Security Advisory (ELSA-2008-0164)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0164");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0164.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5' package(s) announced via the ELSA-2008-0164 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.6.1-17.el5_1.1]
 - add preliminary patch to fix use of uninitialized pointer / double-free in
 KDC (CVE-2008-0062,CVE-2008-0063) (#432620, #432621)
 - add backported patch to fix use-after-free in libgssapi_krb5
 (CVE-2007-5901)
 (#415321)
 - add backported patch to fix double-free in libgssapi_krb5 (CVE-2007-5971)
 (#415351)
 - add preliminary patch to fix incorrect handling of high-numbered
 descriptors
 in the RPC library (CVE-2008-0947) (#433596)
 - fix storage of delegated krb5 credentials when they've been wrapped up in
 spnego (#436460)
 - return a delegated credential handle even if the application didn't pass a
 location to store the flags which would be used to indicate that
 credentials
 were delegated (#436465)
 - add patch to fall back to TCP kpasswd servers for kdc-unreachable,
 can't-resolve-server, and response-too-big errors (#436467)
 - use the right sequence numbers when generating password-set/change
 requests
 for kpasswd servers after the first one (#436468)
 - backport from 1.6.3 to initialize a library-allocated get_init_creds_opt
 structure the same way we would one which was allocated by the calling
 application, to restore kinit's traditional behavior of doing a password
 change right when it detects an expired password (#436470)");

  script_tag(name:"affected", value:"'krb5' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"krb5", rpm:"krb5~1.6.1~17.el5_1.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-devel", rpm:"krb5-devel~1.6.1~17.el5_1.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-libs", rpm:"krb5-libs~1.6.1~17.el5_1.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-server", rpm:"krb5-server~1.6.1~17.el5_1.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"krb5-workstation", rpm:"krb5-workstation~1.6.1~17.el5_1.1", rls:"OracleLinux5"))) {
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
