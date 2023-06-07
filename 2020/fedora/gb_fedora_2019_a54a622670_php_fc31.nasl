# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877150");
  script_version("2021-07-20T02:00:49+0000");
  script_cve_id("CVE-2019-11046", "CVE-2019-11044", "CVE-2019-11045", "CVE-2019-11049", "CVE-2019-11050", "CVE-2019-11047");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-20 02:00:49 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-03 11:15:00 +0000 (Fri, 03 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 07:28:48 +0000 (Thu, 09 Jan 2020)");
  script_name("Fedora Update for php FEDORA-2019-a54a622670");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2019-a54a622670");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XWRQPYXVG43Q7DXMXH6UVWMKWGUW552F");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php'
  package(s) announced via the FEDORA-2019-a54a622670 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PHP is an HTML-embedded scripting language. PHP attempts to make it
easy for developers to write dynamically generated web pages. PHP also
offers built-in database integration for several commercial and
non-commercial database management systems, so writing a
database-enabled webpage with PHP is fairly simple. The most common
use of PHP coding is probably as a replacement for CGI scripts.

The php package contains the module (often referred to as mod_php)
which adds support for the PHP language to Apache HTTP Server.");

  script_tag(name:"affected", value:"'php' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"php", rpm:"php~7.3.13~1.fc31", rls:"FC31"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);