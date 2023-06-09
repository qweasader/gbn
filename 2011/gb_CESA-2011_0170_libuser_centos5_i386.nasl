###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libuser CESA-2011:0170 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017427.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880503");
  script_version("2022-05-31T15:38:36+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:38:36 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_xref(name:"CESA", value:"2011:0170");
  script_cve_id("CVE-2011-0002");
  script_name("CentOS Update for libuser CESA-2011:0170 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libuser'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libuser on CentOS 5");
  script_tag(name:"insight", value:"The libuser library implements a standardized interface for manipulating
  and administering user and group accounts. Sample applications that are
  modeled after applications from the shadow password suite (shadow-utils)
  are included in these packages.

  It was discovered that libuser did not set the password entry correctly
  when creating LDAP (Lightweight Directory Access Protocol) users. If an
  administrator did not assign a password to an LDAP based user account,
  either at account creation with luseradd, or with lpasswd after account
  creation, an attacker could use this flaw to log into that account with a
  default password string that should have been rejected. (CVE-2011-0002)

  Note: LDAP administrators that have used libuser tools to add users should
  check existing user accounts for plain text passwords, and reset them as
  necessary.

  Users of libuser should upgrade to these updated packages, which contain a
  backported patch to correct this issue.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  if ((res = isrpmvuln(pkg:"libuser", rpm:"libuser~0.54.7~2.1.el5_5.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-devel", rpm:"libuser-devel~0.54.7~2.1.el5_5.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
