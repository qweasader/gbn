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
  script_oid("1.3.6.1.4.1.25623.1.0.120714");
  script_cve_id("CVE-2016-5387");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:17 +0000 (Wed, 26 Oct 2016)");
  script_version("2022-09-09T10:12:35+0000");
  script_tag(name:"last_modification", value:"2022-09-09 10:12:35 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:40:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-725)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-725");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-725.html");
  script_xref(name:"URL", value:"https://httpoxy.org/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd24, httpd' package(s) announced via the ALAS-2016-725 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that httpd used the value of the Proxy header from HTTP requests to initialize the HTTP_PROXY environment variable for CGI scripts, which in turn was incorrectly used by certain HTTP client implementations to configure the proxy for outgoing HTTP requests. A remote attacker could possibly use this flaw to redirect HTTP requests performed by a CGI script to an attacker-controlled proxy via a malicious HTTP request (known as the 'httpoxy' class of vulnerabilities).");

  script_tag(name:"affected", value:"'httpd24, httpd' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.31~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.31~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.31~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.31~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.31~1.8.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24", rpm:"httpd24~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-debuginfo", rpm:"httpd24-debuginfo~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-devel", rpm:"httpd24-devel~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-manual", rpm:"httpd24-manual~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd24-tools", rpm:"httpd24-tools~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_ldap", rpm:"mod24_ldap~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_proxy_html", rpm:"mod24_proxy_html~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_session", rpm:"mod24_session~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_ssl", rpm:"mod24_ssl~2.4.23~1.65.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.31~1.8.amzn1", rls:"AMAZON"))) {
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
