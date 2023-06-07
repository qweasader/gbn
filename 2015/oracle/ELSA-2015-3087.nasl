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
  script_oid("1.3.6.1.4.1.25623.1.0.122714");
  script_cve_id("CVE-2015-1335");
  script_tag(name:"creation_date", value:"2015-10-16 05:38:33 +0000 (Fri, 16 Oct 2015)");
  script_version("2022-04-04T14:03:28+0000");
  script_tag(name:"last_modification", value:"2022-04-04 14:03:28 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2015-3087)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=(OracleLinux6|OracleLinux7)");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-3087");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-3087.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lxc' package(s) announced via the ELSA-2015-3087 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.0.7-2.0.12]
- [Orabug 22011867] ol6 ct shutdown script remounts /dev/pts/* devices as
 ro on host system.

[1.0.7-2.0.11]
- [Orabug 21842483] failed to create directory '/RUN/LXC/LOCK//CONTAINER/OL7.1/SNAPS'
- CVE-2015-1335: Protect container mounts against symlinks.
- Fixed build failure on OL6.");

  script_tag(name:"affected", value:"'lxc' package(s) on Oracle Linux 6, Oracle Linux 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~1.0.7~2.0.12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-devel", rpm:"lxc-devel~1.0.7~2.0.12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-libs", rpm:"lxc-libs~1.0.7~2.0.12.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"lxc", rpm:"lxc~1.0.7~2.0.12.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-devel", rpm:"lxc-devel~1.0.7~2.0.12.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lxc-libs", rpm:"lxc-libs~1.0.7~2.0.12.el7", rls:"OracleLinux7"))) {
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
