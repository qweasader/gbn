###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kernel FEDORA-2007-336
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-March/msg00045.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861208");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-02-27 16:23:18 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name:"FEDORA", value:"2007-336");
  script_cve_id("CVE-2007-0005", "CVE-2007-1000", "CVE-2007-0772", "CVE-2007-0006", "CVE-2006-5757");
  script_name("Fedora Update for kernel FEDORA-2007-336");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms", re:"ssh/login/release=FC5");

  script_tag(name:"affected", value:"kernel on Fedora Core 5");
  script_tag(name:"solution", value:"Please install the updated package(s).");

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

if(release == "FC5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ppc/kernel-doc", rpm:"ppc/kernel-doc~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/kernel-debug-devel", rpm:"x86_64/kernel-debug-devel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/kernel", rpm:"x86_64/kernel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/kernel-kdump-devel", rpm:"x86_64/kernel-kdump-devel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/kernel-debug", rpm:"x86_64/kernel-debug~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/kernel-debuginfo", rpm:"x86_64/debug/kernel-debuginfo~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/kernel-kdump", rpm:"x86_64/kernel-kdump~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/kernel-devel", rpm:"x86_64/kernel-devel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/kernel-doc", rpm:"x86_64/kernel-doc~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/kernel-debuginfo", rpm:"i386/debug/kernel-debuginfo~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/kernel-devel", rpm:"i386/kernel-devel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/kernel", rpm:"i386/kernel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/kernel-debuginfo", rpm:"i386/debug/kernel-debuginfo~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/kernel-smp", rpm:"i386/kernel-smp~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/kernel-smp-devel", rpm:"i386/kernel-smp-devel~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/kernel-doc", rpm:"i386/kernel-doc~2.6.20~1.2300.fc5", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}