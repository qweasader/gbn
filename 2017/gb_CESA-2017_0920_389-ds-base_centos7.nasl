###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for 389-ds-base CESA-2017:0920 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882689");
  script_version("2021-09-17T10:01:50+0000");
  script_tag(name:"last_modification", value:"2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-04-14 06:30:08 +0200 (Fri, 14 Apr 2017)");
  script_cve_id("CVE-2017-2668");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for 389-ds-base CESA-2017:0920 centos7");
  script_tag(name:"summary", value:"Check the version of 389-ds-base");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3
(LDAPv3) compliant server. The base packages include the Lightweight Directory
Access Protocol (LDAP) server and command-line utilities for server administration.

Security Fix(es):

  * An invalid pointer dereference flaw was found in the way 389-ds-base
handled LDAP bind requests. A remote unauthenticated attacker could use
this flaw to make ns-slapd crash via a specially crafted LDAP bind request,
resulting in denial of service. (CVE-2017-2668)

Red Hat would like to thank Joachim Jabs (F24) for reporting this issue.

Bug Fix(es):

  * Previously, when adding a filtered role definition that uses the 'nsrole'
virtual attribute in the filter, Directory Server terminated unexpectedly.
A patch has been applied, and now the roles plug-in ignores all virtual
attributes. As a result, an error message is logged when an invalid filter
is used. Additionally, the role is deactivated and Directory Server no
longer fails. (BZ#1429498)

  * In a replication topology, Directory Server incorrectly calculated the
size of string format entries when a lot of entries were deleted. The
calculated size of entries was smaller than the actual required size.
Consequently, Directory Server allocated insufficient memory and terminated
unexpectedly when the data was written to it. With this update, the size of
string format entries is now calculated correctly in the described
situation and Directory Server no longer terminates unexpectedly.
(BZ#1429495)");
  script_tag(name:"affected", value:"389-ds-base on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0920");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-April/022370.html");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.5.10~20.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.3.5.10~20.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.5.10~20.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-snmp", rpm:"389-ds-base-snmp~1.3.5.10~20.el7_3", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
