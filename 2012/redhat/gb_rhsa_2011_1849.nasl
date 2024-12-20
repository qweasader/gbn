# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00044.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870737");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-07-09 10:58:21 +0530 (Mon, 09 Jul 2012)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-4127");
  script_xref(name:"RHSA", value:"2011:1849-01");
  script_name("RedHat Update for kernel RHSA-2011:1849-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fix:

  * Using the SG_IO IOCTL to issue SCSI requests to partitions or LVM volumes
  resulted in the requests being passed to the underlying block device. If a
  privileged user only had access to a single partition or LVM volume, they
  could use this flaw to bypass those restrictions and gain read and write
  access (and be able to issue other SCSI commands) to the entire block
  device.

  In KVM (Kernel-based Virtual Machine) environments using raw format virtio
  disks backed by a partition or LVM volume, a privileged guest user could
  bypass intended restrictions and issue read and write requests (and other
  SCSI commands) on the host, and possibly access the data of other guests
  that reside on the same underlying block device. Partition-based and
  LVM-based storage pools are not used by default. Refer to Red Hat Bugzilla
  bug 752375 for further details and a mitigation script for users who cannot
  apply this update immediately. (CVE-2011-4127, Important)

  Bug fixes:

  * Previously, idle load balancer kick requests from other CPUs could be
  serviced without first receiving an inter-processor interrupt (IPI). This
  could have led to a deadlock. (BZ#750459)

  * This update fixes a performance regression that may have caused processes
  (including KVM guests) to hang for a number of seconds. (BZ#751403)

  * When md_raid1_unplug_device() was called while holding a spinlock, under
  certain device failure conditions, it was possible for the lock to be
  requested again, deeper in the call chain, causing a deadlock. Now,
  md_raid1_unplug_device() is no longer called while holding a spinlock.
  (BZ#755545)

  * In hpet_next_event(), an interrupt could have occurred between the read
  and write of the HPET (High Performance Event Timer) and the value of
  HPET_COUNTER was then beyond that being written to the comparator
  (HPET_Tn_CMP). Consequently, the timers were overdue for up to several
  minutes. Now, a comparison is performed between the value of the counter
  and the comparator in the HPET code. If the counter is beyond the
  comparator, the '-ETIME' error code is returned. (BZ#756426)

  * Index allocation in the virtio-blk module was based on a monotonically
  increasing variable 'index'. Consequently, released indexes were not reused
  and after a period of time, no new were available. Now, virtio-blk uses the
  ida A ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~220.2.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
