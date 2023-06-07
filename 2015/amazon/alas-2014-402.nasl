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
  script_oid("1.3.6.1.4.1.25623.1.0.120497");
  script_cve_id("CVE-2014-5461");
  script_tag(name:"creation_date", value:"2015-09-08 11:27:46 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-07T14:04:51+0000");
  script_tag(name:"last_modification", value:"2022-01-07 14:04:51 +0000 (Fri, 07 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-402)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-402");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-402.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lua' package(s) announced via the ALAS-2014-402 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Buffer overflow in the vararg functions in ldo.c in Lua 5.1 through 5.2.x before 5.2.3 allows context-dependent attackers to cause a denial of service (crash) via a small number of arguments to a function with a large number of fixed arguments.");

  script_tag(name:"affected", value:"'lua' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"lua", rpm:"lua~5.1.4~4.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-debuginfo", rpm:"lua-debuginfo~5.1.4~4.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-devel", rpm:"lua-devel~5.1.4~4.1.9.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-static", rpm:"lua-static~5.1.4~4.1.9.amzn1", rls:"AMAZON"))) {
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