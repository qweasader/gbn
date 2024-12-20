# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881763");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-07-11 10:27:59 +0530 (Thu, 11 Jul 2013)");
  script_cve_id("CVE-2012-6544", "CVE-2012-6545", "CVE-2013-0914", "CVE-2013-1929",
                "CVE-2013-3222", "CVE-2013-3224", "CVE-2013-3231", "CVE-2013-3235");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_name("CentOS Update for kernel CESA-2013:1034 centos5");

  script_xref(name:"CESA", value:"2013:1034");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-July/019845.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * Information leaks in the Linux kernel could allow a local, unprivileged
  user to leak kernel memory to user-space. (CVE-2012-6544, CVE-2012-6545,
  CVE-2013-3222, CVE-2013-3224, CVE-2013-3231, CVE-2013-3235, Low)

  * An information leak was found in the Linux kernel's POSIX signals
  implementation. A local, unprivileged user could use this flaw to bypass
  the Address Space Layout Randomization (ASLR) security feature.
  (CVE-2013-0914, Low)

  * A heap-based buffer overflow in the way the tg3 Ethernet driver parsed
  the vital product data (VPD) of devices could allow an attacker with
  physical access to a system to cause a denial of service or, potentially,
  escalate their privileges. (CVE-2013-1929, Low)

  This update also fixes the following bugs:

  * Previously on system boot, devices with associated Reserved Memory Region
  Reporting (RMRR) information had lost their RMRR information after they
  were removed from the static identity (SI) domain. Consequently, a system
  unexpectedly terminated in an endless loop due to unexpected NMIs triggered
  by DMA errors. This problem was observed on HP ProLiant Generation 7 (G7)
  and 8 (Gen8) systems. This update prevents non-USB devices that have RMRR
  information associated with them from being placed into the SI domain
  during system boot. HP ProLiant G7 and Gen8 systems that contain devices
  with the RMRR information now boot as expected. (BZ#957606)

  * Previously, the kernel's futex wait code used timeouts that had
  granularity in milliseconds. Also, when passing these timeouts to system
  calls, the kernel converted the timeouts to 'jiffies'. Consequently,
  programs could time out inaccurately which could lead to significant
  latency problems in certain environments. This update modifies the futex
  wait code to use a high-resolution timer (hrtimer) so the timeout
  granularity is now in microseconds. Timeouts are no longer converted to
  when passed to system calls. Timeouts passed to programs are now
  accurate and the programs time out as expected. (BZ#958021)

  * A recent change modified the size of the task_struct structure in the
  floating point unit (fpu) counter. However, on Intel Itanium systems, this
  change caused the kernel Application Binary Interface (kABI) to stop
  working properly when a previously compiled module was loaded, resulting in
  a kernel panic. With this update the change causing this bug has been
  reverted ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
