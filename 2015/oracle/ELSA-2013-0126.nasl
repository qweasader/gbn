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
  script_oid("1.3.6.1.4.1.25623.1.0.123760");
  script_cve_id("CVE-2012-2124");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:10 +0000 (Tue, 06 Oct 2015)");
  script_version("2022-04-05T07:26:47+0000");
  script_tag(name:"last_modification", value:"2022-04-05 07:26:47 +0000 (Tue, 05 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0126)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0126");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0126.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail' package(s) announced via the ELSA-2013-0126 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.4.8-21.0.2.el5]
- remove Redhat splash screen images from source

[1.4.8-21.0.1.el5]
- remove Redhat splash screen images
- add README instead of README.RedHat

[1.4.8-21]
- change charset for zh_CN and zh_TW to utf-8 (#508686)

[1.4.8-20]
- fix header encoding issue (#241861)
- fix code producing warnings in the log (#475188)

[1.4.8-19]
- patch for CVE-2010-2813 modified wrong file (#808598)
- correct requirement is mod_php not php (#789353)
- comply with RFC2822 line length limits (#745469)
- document that SELinux boolean httpd_can_sendmail needs to be
 turned on (#745380)
- add support for big UIDs on 32bit machines (#450780)
- do not corrupt html attachments (#359791)");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~21.0.2.el5", rls:"OracleLinux5"))) {
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
