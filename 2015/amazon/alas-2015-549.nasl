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
  script_oid("1.3.6.1.4.1.25623.1.0.120440");
  script_cve_id("CVE-2015-3900", "CVE-2015-4020");
  script_tag(name:"creation_date", value:"2015-09-08 11:26:29 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-06T03:03:01+0000");
  script_tag(name:"last_modification", value:"2022-01-06 03:03:01 +0000 (Thu, 06 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-549)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-549");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-549.html");
  script_xref(name:"URL", value:"https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-009/?fid=6478");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby22' package(s) announced via the ALAS-2015-549 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"RubyGems provides the ability of a domain to direct clients to a separate host that is used to fetch gems and make API calls against. This mechanism is implemented via DNS, specifically a SRV record _rubygems._tcp under the original requested domain. RubyGems did not validate the hostname returned in the SRV record before sending requests to it. (CVE-2015-3900)

As discussed upstream, CVE-2015-4020 is due to an incomplete fix for CVE-2015-3900, which allowed redirection to an arbitrary gem server in any security domain.");

  script_tag(name:"affected", value:"'ruby22' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby22", rpm:"ruby22~2.2.2~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby22-debuginfo", rpm:"ruby22-debuginfo~2.2.2~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby22-devel", rpm:"ruby22-devel~2.2.2~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby22-doc", rpm:"ruby22-doc~2.2.2~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby22-irb", rpm:"ruby22-irb~2.2.2~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby22-libs", rpm:"ruby22-libs~2.2.2~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem22-bigdecimal", rpm:"rubygem22-bigdecimal~1.2.6~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem22-io-console", rpm:"rubygem22-io-console~0.4.3~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem22-psych", rpm:"rubygem22-psych~2.0.8~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems22", rpm:"rubygems22~2.4.5~1.6.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygems22-devel", rpm:"rubygems22-devel~2.4.5~1.6.amzn1", rls:"AMAZON"))) {
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
