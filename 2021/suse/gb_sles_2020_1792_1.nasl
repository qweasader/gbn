# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.1792.1");
  script_cve_id("CVE-2015-2296", "CVE-2018-18074");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-14 20:30:00 +0000 (Wed, 14 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:1792-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:1792-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20201792-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3-requests' package(s) announced via the SUSE-SU-2020:1792-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python3-requests provides the following fix:

python-requests was updated to 2.20.1.

Update to version 2.20.1:

Fixed bug with unintended Authorization header stripping for redirects
 using default ports (http/80, https/443).

Update to version 2.20.0:

Bugfixes

 + Content-Type header parsing is now case-insensitive (e.g. charset=utf8
 v Charset=utf8).
 + Fixed exception leak where certain redirect urls would raise uncaught
 urllib3 exceptions.
 + Requests removes Authorization header from requests redirected from
 https to http on the same hostname. (CVE-2018-18074)
 + should_bypass_proxies now handles URIs without hostnames (e.g. files).

Update to version 2.19.1:

Fixed issue where status_codes.py's init function failed trying to
 append to a __doc__ value of None.

Update to version 2.19.0:

Improvements

 + Warn about possible slowdown with cryptography version < 1.3.4
 + Check host in proxy URL, before forwarding request to adapter.
 + Maintain fragments properly across redirects. (RFC7231 7.1.2)
 + Removed use of cgi module to expedite library load time.
 + Added support for SHA-256 and SHA-512 digest auth algorithms.
 + Minor performance improvement to Request.content.

Bugfixes

 + Parsing empty Link headers with parse_header_links() no longer return
 one bogus entry.
 + Fixed issue where loading the default certificate bundle from a zip
 archive would raise an IOError.
 + Fixed issue with unexpected ImportError on windows system which do not
 support winreg module.
 + DNS resolution in proxy bypass no longer includes the username and
 password in the request. This also fixes the issue of DNS queries
 failing on macOS.
 + Properly normalize adapter prefixes for url comparison.
 + Passing None as a file pointer to the files param no longer raises an
 exception.
 + Calling copy on a RequestsCookieJar will now preserve the cookie
 policy correctly.

Update to version 2.18.4:

Improvements

 + Error messages for invalid headers now include the header name for
 easier debugging

Update to version 2.18.3:

Improvements
 + Running $ python -m requests.help now includes the installed version
 of idna.

Bugfixes
 + Fixed issue where Requests would raise ConnectionError instead
 of SSLError when encountering SSL problems when using urllib3 v1.22.

Add ca-certificates (and ca-certificates-mozilla) to dependencies,
 otherwise https connections will fail.");

  script_tag(name:"affected", value:"'python3-requests' package(s) on SUSE Enterprise Storage 5, SUSE Linux Enterprise Module for Public Cloud 12, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE Manager Proxy 3.2, SUSE Manager Server 3.2, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"python-certifi", rpm:"python-certifi~2018.4.16~3.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-chardet", rpm:"python-chardet~3.0.4~5.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.22~3.20.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-certifi", rpm:"python3-certifi~2018.4.16~3.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-chardet", rpm:"python3-chardet~3.0.4~5.6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.22~3.20.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"python3-certifi", rpm:"python3-certifi~2018.4.16~3.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-chardet", rpm:"python3-chardet~3.0.4~5.6.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.20.1~5.2", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.22~3.20.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"python3-certifi", rpm:"python3-certifi~2018.4.16~3.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-chardet", rpm:"python3-chardet~3.0.4~5.6.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.20.1~5.2", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.22~3.20.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"python-chardet", rpm:"python-chardet~3.0.4~5.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-certifi", rpm:"python3-certifi~2018.4.16~3.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-chardet", rpm:"python3-chardet~3.0.4~5.6.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.20.1~5.2", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.22~3.20.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python-certifi", rpm:"python-certifi~2018.4.16~3.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-chardet", rpm:"python-chardet~3.0.4~5.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.22~3.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-certifi", rpm:"python3-certifi~2018.4.16~3.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-chardet", rpm:"python3-chardet~3.0.4~5.6.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-requests", rpm:"python3-requests~2.20.1~5.2", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-urllib3", rpm:"python3-urllib3~1.22~3.20.1", rls:"SLES12.0SP5"))) {
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
