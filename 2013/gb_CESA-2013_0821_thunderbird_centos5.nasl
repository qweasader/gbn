###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2013:0821 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881732");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-05-17 09:53:13 +0530 (Fri, 17 May 2013)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0801", "CVE-2013-1670", "CVE-2013-1674", "CVE-2013-1675",
                "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678", "CVE-2013-1679",
                "CVE-2013-1680", "CVE-2013-1681");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for thunderbird CESA-2013:0821 centos5");

  script_xref(name:"CESA", value:"2013:0821");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019725.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"thunderbird on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  Several flaws were found in the processing of malformed content. Malicious
  content could cause Thunderbird to crash or, potentially, execute arbitrary
  code with the privileges of the user running Thunderbird. (CVE-2013-0801,
  CVE-2013-1674, CVE-2013-1675, CVE-2013-1676, CVE-2013-1677, CVE-2013-1678,
  CVE-2013-1679, CVE-2013-1680, CVE-2013-1681)

  A flaw was found in the way Thunderbird handled Content Level Constructors.
  Malicious content could use this flaw to perform cross-site scripting (XSS)
  attacks. (CVE-2013-1670)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Christoph Diehl, Christian Holler, Jesse Ruderman,
  Timothy Nikkel, Jeff Walden, Nils, Ms2ger, Abhishek Arya, and Cody Crews as
  the original reporters of these issues.

  Note: All of the above issues cannot be exploited by a specially-crafted
  HTML mail message as JavaScript is disabled by default for mail messages.
  They could be exploited another way in Thunderbird, for example, when
  viewing the full remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 17.0.6 ESR, which corrects these issues. After
  installing the update, Thunderbird must be restarted for the changes to
  take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~17.0.6~1.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
