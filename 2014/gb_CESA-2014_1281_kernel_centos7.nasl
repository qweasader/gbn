# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882026");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-24 06:02:40 +0200 (Wed, 24 Sep 2014)");
  script_cve_id("CVE-2014-3917");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_name("CentOS Update for kernel CESA-2014:1281 centos7");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

  * An out-of-bounds memory access flaw was found in the Linux kernel's
system call auditing implementation. On a system with existing audit rules
defined, a local, unprivileged user could use this flaw to leak kernel
memory to user space or, potentially, crash the system. (CVE-2014-3917,
Moderate)

This update also fixes the following bugs:

  * A bug in the mtip32xx driver could prevent the Micron P420m PCIe SSD
devices with unaligned I/O access from completing the submitted I/O
requests. This resulted in a livelock situation and rendered the Micron
P420m PCIe SSD devices unusable. To fix this problem, mtip32xx now checks
whether an I/O access is unaligned and if so, it uses the correct
semaphore. (BZ#1125776)

  * A series of patches has been backported to improve the functionality of
a touch pad on the latest Lenovo laptops in Red Hat Enterprise Linux 7.
(BZ#1122559)

  * Due to a bug in the bnx2x driver, a network adapter could be unable to
recover from EEH error injection. The network adapter had to be taken
offline and rebooted in order to function properly again. With this update,
the bnx2x driver has been corrected and network adapters now recover from
EEH errors as expected. (BZ#1107722)

  * Previously, if an hrtimer interrupt was delayed, all future pending
hrtimer events that were queued on the same processor were also delayed
until the initial hrtimer event was handled. This could cause all hrtimer
processing to stop for a significant period of time. To prevent this
problem, the kernel has been modified to handle all expired hrtimer events
when handling the initially delayed hrtimer event. (BZ#1113175)

  * A previous change to the nouveau driver introduced a bit shift error,
which resulted in a wrong display resolution being set with some models
of NVIDIA controllers. With this update, the erroneous code has been
corrected, and the affected NVIDIA controllers can now set the correct
display resolution. (BZ#1114869)

  * Due to a NULL pointer dereference bug in the be2net driver, the system
could experience a kernel oops and reboot when disabling a network adapter
after a permanent failure. This problem has been fixed by introducing a
flag to keep track of the setup state. The failing adapter can now be
disabled successfully without a kernel crash. (BZ#1122558)

  * Previously, the Huge Translation Lookaside Buffer (HugeTLB) allowed
access to huge pages access by default. However, huge pages may be
unsupported in some environments, such as a KVM guest on a PowerPC
architecture, and an attempt to access a huge pag ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"CESA", value:"2014:1281");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-September/020581.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.8.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
