###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for nfs-utils MDVA-2011:031 (nfs-utils)
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
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-09/msg00003.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831447");
  script_version("2022-05-31T15:38:36+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:38:36 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2011-09-07 08:58:04 +0200 (Wed, 07 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVA", value:"2011:031");
  script_name("Mandriva Update for nfs-utils MDVA-2011:031 (nfs-utils)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"nfs-utils on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Bugfix release of nfs-utils. Fix broken script 'nfs-server.init'.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.1.3~10.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nfs-utils-clients", rpm:"nfs-utils-clients~1.1.3~10.2mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
