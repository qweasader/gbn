# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881799");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-10-03 10:18:39 +0530 (Thu, 03 Oct 2013)");
  script_cve_id("CVE-2012-3511", "CVE-2013-2141", "CVE-2013-4162");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2013:1292 centos5");

  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues:

  * A use-after-free flaw was found in the madvise() system call
implementation in the Linux kernel. A local, unprivileged user could use
this flaw to cause a denial of service or, potentially, escalate their
privileges. (CVE-2012-3511, Moderate)

  * A flaw was found in the way the Linux kernel's TCP/IP protocol suite
implementation handled IPv6 sockets that used the UDP_CORK option. A local,
unprivileged user could use this flaw to cause a denial of service.
(CVE-2013-4162, Moderate)

  * An information leak flaw in the Linux kernel could allow a local,
unprivileged user to leak kernel memory to user-space. (CVE-2013-2141, Low)

Red Hat would like to thank Hannes Frederic Sowa for reporting
CVE-2013-4162.

This update also fixes the following bugs:

  * A bug in the be2net driver prevented communication between NICs using
be2net. This update applies a patch addressing this problem along with
several other upstream patches that fix various other problems. Traffic
between NICs using the be2net driver now proceeds as expected. (BZ#983864)

  * A recent patch fixing a problem that prevented communication between
NICs using the be2net driver caused the firmware of NICs to become
unresponsive, and thus triggered a kernel panic. The problem was caused by
unnecessary usage of a hardware workaround that allows skipping VLAN tag
insertion. A patch has been applied and the workaround is now used only
when the multi-channel configuration is enabled on the NIC. Note that the
bug only affected the NICs with firmware version 4.2.xxxx. (BZ#999819)

  * A bug in the autofs4 mount expiration code could cause the autofs4
module to falsely report a busy tree of NFS mounts as 'not in use'.
Consequently, automount attempted to unmount the tree and failed with
a 'failed to umount offset' error, leaving the mount tree to appear as
empty directories. A patch has been applied to remove an incorrectly used
autofs dentry mount check and the aforementioned problem no longer occurs.
(BZ#1001488)

  * A race condition in the be_open function in the be2net driver could
trigger the BUG_ON() macro, which resulted in a kernel panic. A patch
addressing this problem has been applied and the race condition is now
avoided by enabling polling before enabling interrupts globally. The
kernel no longer panics in this situation. (BZ#1005239)

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The system must be
rebooted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1292");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-September/019961.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.18.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
