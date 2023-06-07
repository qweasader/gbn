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
  script_oid("1.3.6.1.4.1.25623.1.0.120103");
  script_cve_id("CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"creation_date", value:"2015-09-08 11:17:29 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-07T03:03:10+0000");
  script_tag(name:"last_modification", value:"2022-01-07 03:03:10 +0000 (Fri, 07 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-388)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-388");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-388.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd' package(s) announced via the ALAS-2014-388 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition flaw, leading to heap-based buffer overflows, was found in the mod_status httpd module. A remote attacker able to access a status page served by mod_status on a server using a threaded Multi-Processing Module (MPM) could send a specially crafted request that would cause the httpd child process to crash or, possibly, allow the attacker to execute arbitrary code with the privileges of the 'apache' user. (CVE-2014-0226)

A denial of service flaw was found in the way httpd's mod_deflate module handled request body decompression (configured via the 'DEFLATE' input filter). A remote attacker able to send a request whose body would be decompressed could use this flaw to consume an excessive amount of system memory and CPU on the target system. (CVE-2014-0118)

A denial of service flaw was found in the way httpd's mod_cgid module executed CGI scripts that did not read data from the standard input. A remote attacker could submit a specially crafted request that would cause the httpd child process to hang indefinitely. (CVE-2014-0231)");

  script_tag(name:"affected", value:"'httpd' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.27~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-debuginfo", rpm:"httpd-debuginfo~2.2.27~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.27~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.27~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"httpd-tools", rpm:"httpd-tools~2.2.27~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.27~1.3.amzn1", rls:"AMAZON"))) {
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
