###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ImageMagick FEDORA-2007-414
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/fedora-package-announce/2007-April/msg00047.html");
  script_oid("1.3.6.1.4.1.25623.1.0.861508");
  script_version("2022-02-15T14:39:48+0000");
  script_tag(name:"last_modification", value:"2022-02-15 14:39:48 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"FEDORA", value:"2007-414");
  script_cve_id("CVE-2007-1797", "CVE-2006-5456", "CVE-2006-3743", "CVE-2006-4144");
  script_name("Fedora Update for ImageMagick FEDORA-2007-414");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms", re:"ssh/login/release=FC5");

  script_tag(name:"affected", value:"ImageMagick on Fedora Core 5");

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

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-c++-devel", rpm:"x86_64/ImageMagick-c++-devel~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-c++", rpm:"x86_64/ImageMagick-c++~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick", rpm:"x86_64/ImageMagick~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/ImageMagick-debuginfo", rpm:"x86_64/debug/ImageMagick-debuginfo~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-perl", rpm:"x86_64/ImageMagick-perl~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-devel", rpm:"x86_64/ImageMagick-devel~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick", rpm:"i386/ImageMagick~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-c++-devel", rpm:"i386/ImageMagick-c++-devel~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-perl", rpm:"i386/ImageMagick-perl~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/ImageMagick-debuginfo", rpm:"i386/debug/ImageMagick-debuginfo~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-c++", rpm:"i386/ImageMagick-c++~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-devel", rpm:"i386/ImageMagick-devel~6.2.5.4~4.2.1.fc5.8", rls:"FC5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
