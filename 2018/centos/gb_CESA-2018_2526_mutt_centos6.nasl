###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2526_mutt_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for mutt CESA-2018:2526 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882937");
  script_version("2021-05-25T06:00:12+0200");
  script_tag(name:"last_modification", value:"2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)");
  script_tag(name:"creation_date", value:"2018-08-21 06:41:28 +0200 (Tue, 21 Aug 2018)");
  script_cve_id("CVE-2018-14354", "CVE-2018-14357", "CVE-2018-14362");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for mutt CESA-2018:2526 centos6");
  script_tag(name:"summary", value:"Check the version of mutt");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Mutt is a low resource, highly configurable, text-based MIME e-mail client.
Mutt supports most e-mail storing formats, such as mbox and Maildir, as
well as most protocols, including POP3 and IMAP.

Security Fix(es):

  * mutt: Remote code injection vulnerability to an IMAP mailbox
(CVE-2018-14354)

  * mutt: Remote Code Execution via backquote characters (CVE-2018-14357)

  * mutt: POP body caching path traversal vulnerability (CVE-2018-14362)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");
  script_tag(name:"affected", value:"mutt on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2526");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-August/022988.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.5.20~9.20091214hg736b6a.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}