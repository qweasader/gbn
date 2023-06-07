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
  script_oid("1.3.6.1.4.1.25623.1.0.120702");
  script_cve_id("CVE-2016-4051", "CVE-2016-4052", "CVE-2016-4053", "CVE-2016-4054", "CVE-2016-4554", "CVE-2016-4556");
  script_tag(name:"creation_date", value:"2016-10-26 12:38:12 +0000 (Wed, 26 Oct 2016)");
  script_version("2021-12-20T13:08:45+0000");
  script_tag(name:"last_modification", value:"2021-12-20 13:08:45 +0000 (Mon, 20 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-713)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-713");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-713.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the ALAS-2016-713 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow flaw was found in the way the Squid cachemgr.cgi utility processed remotely relayed Squid input. When the CGI interface utility is used, a remote attacker could possibly use this flaw to execute arbitrary code. (CVE-2016-4051)

Buffer overflow and input validation flaws were found in the way Squid processed ESI responses. If Squid was used as a reverse proxy, or for TLS/HTTPS interception, a remote attacker able to control ESI components on an HTTP server could use these flaws to crash Squid, disclose parts of the stack memory, or possibly execute arbitrary code as the user running Squid. (CVE-2016-4052, CVE-2016-4053, CVE-2016-4054)

An input validation flaw was found in Squid's mime_get_header_field() function, which is used to search for headers within HTTP requests. An attacker could send an HTTP request from the client side with specially crafted header Host header that bypasses same-origin security protections, causing Squid operating as interception or reverse-proxy to contact the wrong origin server. It could also be used for cache poisoning for client not following RFC 7230. (CVE-2016-4554)

An incorrect reference counting flaw was found in the way Squid processes ESI responses. If Squid is configured as reverse-proxy, for TLS/HTTPS interception, an attacker controlling a server accessed by Squid, could crash the squid worker, causing a Denial of Service attack. (CVE-2016-4556)");

  script_tag(name:"affected", value:"'squid' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~3.1.23~16.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-debuginfo", rpm:"squid-debuginfo~3.1.23~16.21.amzn1", rls:"AMAZON"))) {
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
