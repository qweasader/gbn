# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-January/017245.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880459");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-31 15:15:14 +0100 (Mon, 31 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0162");
  script_cve_id("CVE-2010-3859", "CVE-2010-3876", "CVE-2010-4072", "CVE-2010-4073", "CVE-2010-4075", "CVE-2010-4080", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4242", "CVE-2010-4249", "CVE-2010-4258");
  script_name("CentOS Update for kernel CESA-2011:0162 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"kernel on CentOS 4");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A heap overflow flaw was found in the Linux kernel's Transparent
  Inter-Process Communication protocol (TIPC) implementation. A local,
  unprivileged user could use this flaw to escalate their privileges.
  (CVE-2010-3859, Important)

  * Missing sanity checks were found in gdth_ioctl_alloc() in the gdth driver
  in the Linux kernel. A local user with access to '/dev/gdth' on a 64-bit
  system could use these flaws to cause a denial of service or escalate their
  privileges. (CVE-2010-4157, Moderate)

  * A NULL pointer dereference flaw was found in the Bluetooth HCI UART
  driver in the Linux kernel. A local, unprivileged user could use this flaw
  to cause a denial of service. (CVE-2010-4242, Moderate)

  * A flaw was found in the Linux kernel's garbage collector for AF_UNIX
  sockets. A local, unprivileged user could use this flaw to trigger a
  denial of service (out-of-memory condition). (CVE-2010-4249, Moderate)

  * Missing initialization flaws were found in the Linux kernel. A local,
  unprivileged user could use these flaws to cause information leaks.
  (CVE-2010-3876, CVE-2010-4072, CVE-2010-4073, CVE-2010-4075, CVE-2010-4080,
  CVE-2010-4083, CVE-2010-4158, Low)

  Red Hat would like to thank Alan Cox for reporting CVE-2010-4242, Vegard
  Nossum for reporting CVE-2010-4249, Vasiliy Kulikov for reporting
  CVE-2010-3876, Kees Cook for reporting CVE-2010-4072, and Dan Rosenberg for
  reporting CVE-2010-4073, CVE-2010-4075, CVE-2010-4080, CVE-2010-4083, and
  CVE-2010-4158.

  This update also fixes the following bugs:

  * A flaw was found in the Linux kernel where, if used in conjunction with
  another flaw that can result in a kernel Oops, could possibly lead to
  privilege escalation. It does not affect Red Hat Enterprise Linux 4 as the
  sysctl panic_on_oops variable is turned on by default. However, as a
  preventive measure if the variable is turned off by an administrator, this
  update addresses the issue. Red Hat would like to thank Nelson Elhage for
  reporting this vulnerability. (BZ#659568)

  * On Intel I/O Controller Hub 9 (ICH9) hardware, jumbo frame support is
  achieved by using page-based sk_buff buffers without any packet split. The
  entire frame data is copied to the page(s) rather than some to the
  skb->data area and some to the page(s) when performing a typical
  packet-split. This caused problems with the filtering code and frames were
  getting dropped before they were received by list ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.35.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
