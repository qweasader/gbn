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
  script_oid("1.3.6.1.4.1.25623.1.0.120436");
  script_cve_id("CVE-2013-3567");
  script_tag(name:"creation_date", value:"2015-09-08 11:26:20 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-05T14:03:08+0000");
  script_tag(name:"last_modification", value:"2022-01-05 14:03:08 +0000 (Wed, 05 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2013-213)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2013-213");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2013-213.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'puppet' package(s) announced via the ALAS-2013-213 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Puppet 2.7.x before 2.7.22 and 3.2.x before 3.2.2, and Puppet Enterprise before 2.8.2, deserializes untrusted YAML, which allows remote attackers to instantiate arbitrary Ruby classes and execute arbitrary code via a crafted REST API call.");

  script_tag(name:"affected", value:"'puppet' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"puppet", rpm:"puppet~2.7.22~1.0.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"puppet-debuginfo", rpm:"puppet-debuginfo~2.7.22~1.0.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"puppet-server", rpm:"puppet-server~2.7.22~1.0.amzn1", rls:"AMAZON"))) {
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