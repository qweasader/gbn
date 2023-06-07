###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for curl CESA-2017:3263 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882804");
  script_version("2021-09-08T12:01:36+0000");
  script_tag(name:"last_modification", value:"2021-09-08 12:01:36 +0000 (Wed, 08 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-11-28 07:19:08 +0100 (Tue, 28 Nov 2017)");
  script_cve_id("CVE-2017-1000257");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for curl CESA-2017:3263 centos7");
  script_tag(name:"summary", value:"Check the version of curl");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The curl packages provide the libcurl
library and the curl utility for downloading files from servers using various
protocols, including HTTP, FTP, and LDAP.

Security Fix(es):

  * A buffer overrun flaw was found in the IMAP handler of libcurl. By
tricking an unsuspecting user into connecting to a malicious IMAP server,
an attacker could exploit this flaw to potentially cause information
disclosure or crash the application. (CVE-2017-1000257)

Red Hat would like to thank the Curl project for reporting this issue.
Upstream acknowledges Brian Carpenter and the OSS-Fuzz project as the
original reporters.");
  script_tag(name:"affected", value:"curl on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:3263");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-November/022630.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.29.0~42.el7_4.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.29.0~42.el7_4.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.29.0~42.el7_4.1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
