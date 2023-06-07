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
  script_oid("1.3.6.1.4.1.25623.1.0.122939");
  script_cve_id("CVE-2015-5370", "CVE-2016-2111", "CVE-2016-2112", "CVE-2016-2115", "CVE-2016-2118");
  script_tag(name:"creation_date", value:"2016-05-09 11:24:55 +0000 (Mon, 09 May 2016)");
  script_version("2021-09-20T10:01:48+0000");
  script_tag(name:"last_modification", value:"2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-27 17:17:00 +0000 (Fri, 27 Sep 2019)");

  script_name("Oracle: Security Advisory (ELSA-2016-0611)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2016-0611");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2016-0611.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the ELSA-2016-0611 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[3.6.23-30.0.1]
- Remove use-after-free talloc_tos() inlined function problem (John Haxby) [orabug 18253258]

[3.6.23-30]
- related: #1322686 - Update manpages

[3.6.23-29]
- related: #1322686 - Update CVE patchset

[3.6.23-28]
- related: #1322686 - Update manpages

[3.6.23-27]
- related: #1322686 - Update CVE patchset

[3.6.23-26]
- resolves: #1322686 - Fix CVE-2015-5370
- resolves: #1322686 - Fix CVE-2016-2110
- resolves: #1322686 - Fix CVE-2016-2111
- resolves: #1322686 - Fix CVE-2016-2112
- resolves: #1322686 - Fix CVE-2016-2115
- resolves: #1322686 - Fix CVE-2016-2118 (Known as Badlock)");

  script_tag(name:"affected", value:"'samba' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-doc", rpm:"samba-doc~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-domainjoin-gui", rpm:"samba-domainjoin-gui~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-glusterfs", rpm:"samba-glusterfs~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-clients", rpm:"samba-winbind-clients~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-devel", rpm:"samba-winbind-devel~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-krb5-locator", rpm:"samba-winbind-krb5-locator~3.6.23~30.0.1.el6_7", rls:"OracleLinux6"))) {
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
