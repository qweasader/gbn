###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2017:0323 centos5
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
  script_oid("1.3.6.1.4.1.25623.1.0.882668");
  script_version("2021-09-10T11:01:38+0000");
  script_tag(name:"last_modification", value:"2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"creation_date", value:"2017-03-02 12:09:24 +0530 (Thu, 02 Mar 2017)");
  script_cve_id("CVE-2017-2634", "CVE-2017-6074");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:26:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2017:0323 centos5");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * A use-after-free flaw was found in the way the Linux kernel's Datagram
Congestion Control Protocol (DCCP) implementation freed SKB (socket buffer)
resources for a DCCP_PKT_REQUEST packet when the IPV6_RECVPKTINFO option is
set on the socket. A local, unprivileged user could use this flaw to alter
the kernel memory, allowing them to escalate their privileges on the
system. (CVE-2017-6074, Important)

  * It was found that the Linux kernel's Datagram Congestion Control Protocol
(DCCP) implementation used the IPv4-only inet_sk_rebuild_header() function
for both IPv4 and IPv6 DCCP connections, which could result in memory
corruptions. A remote attacker could use this flaw to crash the system.
(CVE-2017-2634, Moderate)

Important: This update disables the DCCP kernel module at load time by
using the kernel module blacklist method. The module is disabled in an
attempt to reduce further exposure to additional issues. Please see Red Hat
Bugzilla (BZ#1425177) for additional information.

Red Hat would like to thank Andrey Konovalov (Google) for reporting
CVE-2017-6074. The CVE-2017-2634 issue was discovered by Wade Mealing (Red
Hat Product Security).");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:0323");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-February/022293.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~419.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
