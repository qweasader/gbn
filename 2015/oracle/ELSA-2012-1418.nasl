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
  script_oid("1.3.6.1.4.1.25623.1.0.123693");
  script_cve_id("CVE-2012-4512", "CVE-2012-4513");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:19 +0000 (Tue, 06 Oct 2015)");
  script_version("2021-10-18T09:03:47+0000");
  script_tag(name:"last_modification", value:"2021-10-18 09:03:47 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-14 16:39:00 +0000 (Fri, 14 Feb 2020)");

  script_name("Oracle: Security Advisory (ELSA-2012-1418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1418");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1418.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdelibs' package(s) announced via the ELSA-2012-1418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[6:4.3.4-19.0.1]
- rebuild it with new rules
 add build requirement of installing libXdmcp-devel

[6:4.3.4-19]
- fix multilib conflict

[6:4.3.4-18]
- Resolves: bz#866230, CVE-2012-4512 CVE-2012-4513

[4.3.4-17]
- Resolves: bz#754161, bz#587016, bz#682611, bz#734734, bz#826114, respin

[6:4.3.4-16]
- Resolves: bz#754161, stop/warn when a subdir is not accessible when copying

[6:4.3.4-15]
- Resolves: bz#587016, print dialogue does not remember previous settings
- Resolves: bz#682611, Konqueror splash page in zh_TW is wrong
- Resolves: bz#734734, plasma eating up cpu-time when systemtray some icon
- Resolves: bz#826114, konqueror crash when trying to add 'Terminal Emulator' to main menu bar");

  script_tag(name:"affected", value:"'kdelibs' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"kdelibs", rpm:"kdelibs~4.3.4~19.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs-apidocs", rpm:"kdelibs-apidocs~4.3.4~19.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs-common", rpm:"kdelibs-common~4.3.4~19.0.1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kdelibs-devel", rpm:"kdelibs-devel~4.3.4~19.0.1.el6", rls:"OracleLinux6"))) {
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
