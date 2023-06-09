###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for axis RHSA-2013:0683-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-March/msg00069.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870971");
  script_version("2022-05-31T14:55:16+0100");
  script_tag(name:"last_modification", value:"2022-05-31 14:55:16 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2013-03-28 09:48:49 +0530 (Thu, 28 Mar 2013)");
  script_cve_id("CVE-2012-5784");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_xref(name:"RHSA", value:"2013:0683-01");
  script_name("RedHat Update for axis RHSA-2013:0683-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'axis'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"axis on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Apache Axis is an implementation of SOAP (Simple Object Access Protocol).
  It can be used to build both web service clients and servers.

  Apache Axis did not verify that the server hostname matched the domain name
  in the subject's Common Name (CN) or subjectAltName field in X.509
  certificates. This could allow a man-in-the-middle attacker to spoof an SSL
  server if they had a certificate that was valid for any domain name.
  (CVE-2012-5784)

  All users of axis are advised to upgrade to these updated packages, which
  correct this issue. Applications using Apache Axis must be restarted for
  this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"axis", rpm:"axis~1.2.1~2jpp.7.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"axis-debuginfo", rpm:"axis-debuginfo~1.2.1~2jpp.7.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"axis-javadoc", rpm:"axis-javadoc~1.2.1~2jpp.7.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"axis-manual", rpm:"axis-manual~1.2.1~2jpp.7.el5_9", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
