###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2013:0627 centos5
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
  script_tag(name:"affected", value:"thunderbird on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  A flaw was found in the processing of malformed content. Malicious content
  could cause Thunderbird to crash or execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2013-0787)

  Red Hat would like to thank the Mozilla project for reporting this issue.
  Upstream acknowledges VUPEN Security via the TippingPoint Zero Day
  Initiative project as the original reporter.

  Note: This issue cannot be exploited by a specially-crafted HTML mail
  message as JavaScript is disabled by default for mail messages. It could
  be exploited another way in Thunderbird, for example, when viewing the full
  remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  corrects this issue. After installing the update, Thunderbird must be
  restarted for the changes to take effect.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019643.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881685");
  script_version("2022-05-31T14:55:16+0100");
  script_tag(name:"last_modification", value:"2022-05-31 14:55:16 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2013-03-15 09:52:08 +0530 (Fri, 15 Mar 2013)");
  script_cve_id("CVE-2013-0787");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:0627");
  script_name("CentOS Update for thunderbird CESA-2013:0627 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~17.0.3~2.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
