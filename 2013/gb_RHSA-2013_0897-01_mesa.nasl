###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for mesa RHSA-2013:0897-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871006");
  script_version("2022-05-31T14:55:16+0100");
  script_tag(name:"last_modification", value:"2022-05-31 14:55:16 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2013-06-04 09:18:35 +0530 (Tue, 04 Jun 2013)");
  script_cve_id("CVE-2013-1872", "CVE-2013-1993");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for mesa RHSA-2013:0897-01");

  script_xref(name:"RHSA", value:"2013:0897-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-June/msg00003.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mesa'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"mesa on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Mesa provides a 3D graphics API that is compatible with Open Graphics
  Library (OpenGL). It also provides hardware-accelerated drivers for many
  popular graphics chips.

  An out-of-bounds access flaw was found in Mesa. If an application using
  Mesa exposed the Mesa API to untrusted inputs (Mozilla Firefox does
  this), an attacker could cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2013-1872)

  It was found that Mesa did not correctly validate messages from the X
  server. A malicious X server could cause an application using Mesa to crash
  or, potentially, execute arbitrary code with the privileges of the user
  running the application. (CVE-2013-1993)

  All users of Mesa are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. All running
  applications linked against Mesa must be restarted for this update to take
  effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"glx-utils", rpm:"glx-utils~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-debuginfo", rpm:"mesa-debuginfo~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-dri-drivers", rpm:"mesa-dri-drivers~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-dri-filesystem", rpm:"mesa-dri-filesystem~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGL", rpm:"mesa-libGL~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGL-devel", rpm:"mesa-libGL-devel~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGLU", rpm:"mesa-libGLU~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mesa-libGLU-devel", rpm:"mesa-libGLU-devel~9.0~0.8.el6_4.3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}