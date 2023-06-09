###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for firefox CESA-2013:0144 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019050.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881553");
  script_version("2022-05-31T14:55:16+0100");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-05-31 14:55:16 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2013-01-11 16:43:03 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2013-0744", "CVE-2013-0746", "CVE-2013-0748", "CVE-2013-0750",
                "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0758", "CVE-2013-0759",
                "CVE-2013-0762", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0769");
  script_xref(name:"CESA", value:"2013:0144");
  script_name("CentOS Update for firefox CESA-2013:0144 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"firefox on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Mozilla Firefox is an open source web browser. XULRunner provides the XUL
  Runtime environment for Mozilla Firefox.

  Several flaws were found in the processing of malformed web content. A web
  page containing malicious content could cause Firefox to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2013-0744, CVE-2013-0746, CVE-2013-0750, CVE-2013-0753,
  CVE-2013-0754, CVE-2013-0762, CVE-2013-0766, CVE-2013-0767, CVE-2013-0769)

  A flaw was found in the way Chrome Object Wrappers were implemented.
  Malicious content could be used to cause Firefox to execute arbitrary code
  via plug-ins installed in Firefox. (CVE-2013-0758)

  A flaw in the way Firefox displayed URL values in the address bar could
  allow a malicious site or user to perform a phishing attack.
  (CVE-2013-0759)

  An information disclosure flaw was found in the way certain JavaScript
  functions were implemented in Firefox. An attacker could use this flaw to
  bypass Address Space Layout Randomization (ASLR) and other security
  restrictions. (CVE-2013-0748)

  For technical details regarding these flaws, refer to the Mozilla security
  advisories for Firefox 10.0.12 ESR. You can find a link to the Mozilla
  advisories in the References section of this erratum.

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Atte Kettunen, Boris Zbarsky, pa_kt, regenrecht,
  Abhishek Arya, Christoph Diehl, Christian Holler, Mats Palmgren, Chiaki
  Ishikawa, Mariusz Mlynski, Masato Kinugawa, and Jesse Ruderman as the
  original reporters of these issues.

  All Firefox users should upgrade to these updated packages, which contain
  Firefox version 10.0.12 ESR, which corrects these issues. After installing
  the update, Firefox must be restarted for the changes to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~10.0.12~1.el6.centos", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
