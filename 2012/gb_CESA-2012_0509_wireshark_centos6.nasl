###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for wireshark CESA-2012:0509 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-April/018591.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881173");
  script_version("2022-05-31T15:35:19+0100");
  script_tag(name:"last_modification", value:"2022-05-31 15:35:19 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2012-07-30 16:32:44 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1143", "CVE-2011-1590", "CVE-2011-1957", "CVE-2011-1958",
                "CVE-2011-1959", "CVE-2011-2174", "CVE-2011-2175", "CVE-2011-2597",
                "CVE-2011-2698", "CVE-2011-4102", "CVE-2012-0041", "CVE-2012-0042",
                "CVE-2012-0066", "CVE-2012-0067", "CVE-2012-1595");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2012:0509");
  script_name("CentOS Update for wireshark CESA-2012:0509 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"wireshark on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Wireshark is a program for monitoring network traffic. Wireshark was
  previously known as Ethereal.

  Several flaws were found in Wireshark. If Wireshark read a malformed packet
  off a network or opened a malicious dump file, it could crash or, possibly,
  execute arbitrary code as the user running Wireshark. (CVE-2011-1590,
  CVE-2011-4102, CVE-2012-1595)

  Several denial of service flaws were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off a network, or
  opened a malicious dump file. (CVE-2011-1143, CVE-2011-1957, CVE-2011-1958,
  CVE-2011-1959, CVE-2011-2174, CVE-2011-2175, CVE-2011-2597, CVE-2011-2698,
  CVE-2012-0041, CVE-2012-0042, CVE-2012-0067, CVE-2012-0066)

  Users of Wireshark should upgrade to these updated packages, which contain
  backported patches to correct these issues. All running instances of
  Wireshark must be restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.2.15~2.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~1.2.15~2.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.2.15~2.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
