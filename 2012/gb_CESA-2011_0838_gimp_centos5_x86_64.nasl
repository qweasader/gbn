###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gimp CESA-2011:0838 centos5 x86_64
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-May/017598.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881435");
  script_version("2022-05-31T15:35:19+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:35:19 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2012-07-30 17:51:54 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2009-1570", "CVE-2010-4540", "CVE-2010-4541", "CVE-2010-4542",
                "CVE-2010-4543", "CVE-2011-1178");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0838");
  script_name("CentOS Update for gimp CESA-2011:0838 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gimp'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gimp on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The GIMP (GNU Image Manipulation Program) is an image composition and
  editing program.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the GIMP's Microsoft Windows Bitmap (BMP) and Personal Computer
  eXchange (PCX) image file plug-ins. An attacker could create a
  specially-crafted BMP or PCX image file that, when opened, could cause the
  relevant plug-in to crash or, potentially, execute arbitrary code with the
  privileges of the user running the GIMP. (CVE-2009-1570, CVE-2011-1178)

  A heap-based buffer overflow flaw was found in the GIMP's Paint Shop Pro
  (PSP) image file plug-in. An attacker could create a specially-crafted PSP
  image file that, when opened, could cause the PSP plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the GIMP. (CVE-2010-4543)

  A stack-based buffer overflow flaw was found in the GIMP's Lightning,
  Sphere Designer, and Gfig image filters. An attacker could create a
  specially-crafted Lightning, Sphere Designer, or Gfig filter configuration
  file that, when opened, could cause the relevant plug-in to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the GIMP. (CVE-2010-4540, CVE-2010-4541, CVE-2010-4542)

  Red Hat would like to thank Stefan Cornelius of Secunia Research for
  responsibly reporting the CVE-2009-1570 flaw.

  Users of the GIMP are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. The GIMP must be
  restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"gimp", rpm:"gimp~2.2.13~2.0.7.el5_6.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-devel", rpm:"gimp-devel~2.2.13~2.0.7.el5_6.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gimp-libs", rpm:"gimp-libs~2.2.13~2.0.7.el5_6.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}