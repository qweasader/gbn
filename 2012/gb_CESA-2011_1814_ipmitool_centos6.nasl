###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ipmitool CESA-2011:1814 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-December/018341.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881362");
  script_version("2022-05-31T15:35:19+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:35:19 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2012-07-30 17:35:37 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4339");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_xref(name:"CESA", value:"2011:1814");
  script_name("CentOS Update for ipmitool CESA-2011:1814 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipmitool'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"ipmitool on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The ipmitool package contains a command line utility for interfacing with
  devices that support the Intelligent Platform Management Interface (IPMI)
  specification. IPMI is an open standard for machine health, inventory, and
  remote power control.

  It was discovered that the IPMI event daemon (ipmievd) created its process
  ID (PID) file with world-writable permissions. A local user could use this
  flaw to make the ipmievd init script kill an arbitrary process when the
  ipmievd daemon is stopped or restarted. (CVE-2011-4339)

  All users of ipmitool are advised to upgrade to this updated package, which
  contains a backported patch to correct this issue. After installing this
  update, the IPMI event daemon (ipmievd) will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"ipmitool", rpm:"ipmitool~1.8.11~12.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
