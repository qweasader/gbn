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
  script_oid("1.3.6.1.4.1.25623.1.0.120531");
  script_cve_id("CVE-2015-3143", "CVE-2015-3144", "CVE-2015-3145", "CVE-2015-3148");
  script_tag(name:"creation_date", value:"2015-09-08 11:28:43 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-514)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-514");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-514.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the ALAS-2015-514 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libcurl could incorrectly reuse NTLM-authenticated connections for subsequent unauthenticated requests to the same host. If an application using libcurl established an NTLM-authenticated connection to a server, and sent subsequent unauthenticated requests to the same server, the unauthenticated requests could be sent over the NTLM-authenticated connection, appearing as if they were sent by the NTLM authenticated user. (CVE-2015-3143)

It was discovered that libcurl could incorrectly reuse Negotiate authenticated HTTP connections for subsequent requests. If an application using libcurl established a Negotiate authenticated HTTP connection to a server and sent subsequent requests with different credentials, the connection could be re-used with the initial set of credentials instead of using the new ones. (CVE-2015-3148)

It was discovered that libcurl did not properly process cookies with a specially crafted 'path' element. If an application using libcurl connected to a malicious HTTP server sending specially crafted 'Set-Cookies' headers, this could lead to an out-of-bounds read, and possibly cause that application to crash. (CVE-2015-3145)

It was discovered that libcurl did not properly process zero-length host names. If an attacker could trick an application using libcurl into processing zero-length host names, this could lead to an out-of-bounds read, and possibly cause that application to crash. (CVE-2015-3144)");

  script_tag(name:"affected", value:"'curl' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.40.0~3.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.40.0~3.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.40.0~3.50.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.40.0~3.50.amzn1", rls:"AMAZON"))) {
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
