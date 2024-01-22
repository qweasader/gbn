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
  script_oid("1.3.6.1.4.1.25623.1.0.120035");
  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-9365");
  script_tag(name:"creation_date", value:"2015-09-08 11:15:50 +0000 (Tue, 08 Sep 2015)");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-21 17:44:00 +0000 (Wed, 21 Oct 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-552)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-552");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-552.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python27' package(s) announced via the ALAS-2015-552 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that multiple Python standard library modules implementing network protocols (such as httplib or smtplib) failed to restrict sizes of server responses. A malicious server could cause a client using one of the affected modules to consume an excessive amount of memory.(CVE-2013-1752)

It was discovered that the Python xmlrpclib did not restrict the size of a gzip compressed HTTP responses. A malicious XMLRPC server could cause an XMLRPC client using xmlrpclib to consume an excessive amount of memory. (CVE-2013-1753)

The Python standard library HTTP client modules (such as httplib or urllib) did not perform verification of TLS/SSL certificates when connecting to HTTPS servers. A man-in-the-middle attacker could use this flaw to hijack connections and eavesdrop or modify transferred data.(CVE-2014-9365)");

  script_tag(name:"affected", value:"'python27' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"python27", rpm:"python27~2.7.9~4.114.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-debuginfo", rpm:"python27-debuginfo~2.7.9~4.114.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-devel", rpm:"python27-devel~2.7.9~4.114.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-libs", rpm:"python27-libs~2.7.9~4.114.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-test", rpm:"python27-test~2.7.9~4.114.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python27-tools", rpm:"python27-tools~2.7.9~4.114.amzn1", rls:"AMAZON"))) {
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
