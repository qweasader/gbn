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
  script_oid("1.3.6.1.4.1.25623.1.0.123887");
  script_cve_id("CVE-2012-1586");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:52 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T03:03:58+0000");
  script_tag(name:"last_modification", value:"2022-04-05 03:03:58 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2012-0902)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0902");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0902.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils' package(s) announced via the ELSA-2012-0902 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[4.8.1-10]
- mount.cifs: don't allow unprivileged users to mount onto dirs they can't chdir into (bz 812782)

[4.8.1-9]
- cifs.upcall: use krb5_sname_to_principal to construct principal name (bz 805490)

[4.8.1-8]
- mount.cifs: add backupuid=/backupgid= mount options (bz 806337)

[4.8.1-7]
- RFE: Improve selection of SPNs with cifs.upcall (bz 748757)
- mount.cifs does not use KRB5_CONFIG (bz 748756)
[creates additional entries in /etc/mtab (bz 770004)]
- mount.cifs does not honor the uid/gid=username option, only the uid/gid=# option (bz 796463)

[4.8.1-6]
- undocumented mount.cifs options (bz 769923)");

  script_tag(name:"affected", value:"'cifs-utils' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"cifs-utils", rpm:"cifs-utils~4.8.1~10.el6", rls:"OracleLinux6"))) {
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
