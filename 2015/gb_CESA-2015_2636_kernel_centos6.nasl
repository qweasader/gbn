# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882342");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-16 05:50:17 +0100 (Wed, 16 Dec 2015)");
  script_cve_id("CVE-2015-2925", "CVE-2015-5307", "CVE-2015-7613", "CVE-2015-7872",
                "CVE-2015-8104");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2015:2636 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

  * A flaw was found in the way the Linux kernel's file system implementation
handled rename operations in which the source was inside and the
destination was outside of a bind mount. A privileged user inside a
container could use this flaw to escape the bind mount and, potentially,
escalate their privileges on the system. (CVE-2015-2925, Important)

  * It was found that the x86 ISA (Instruction Set Architecture) is prone to
a denial of service attack inside a virtualized environment in the form of
an infinite loop in the microcode due to the way (sequential) delivering of
benign exceptions such as #AC (alignment check exception) and #DB (debug
exception) is handled. A privileged user inside a guest could use these
flaws to create denial of service conditions on the host kernel.
(CVE-2015-5307, CVE-2015-8104, Important)

  * A race condition flaw was found in the way the Linux kernel's IPC
subsystem initialized certain fields in an IPC object structure that were
later used for permission checking before inserting the object into a
globally visible list. A local, unprivileged user could potentially use
this flaw to elevate their privileges on the system. (CVE-2015-7613,
Important)

  * It was found that the Linux kernel's keys subsystem did not correctly
garbage collect uninstantiated keyrings. A local attacker could use this
flaw to crash the system or, potentially, escalate their privileges on
the system. (CVE-2015-7872, Important)

Red Hat would like to thank Ben Serebrin of Google Inc. for reporting the
CVE-2015-5307 issue.

This update also fixes the following bugs:

  * Previously, Human Interface Device (HID) ran a report on an unaligned
buffer, which could cause a page fault interrupt and an oops when the end
of the report was read. This update fixes this bug by padding the end of
the report with extra bytes, so the reading of the report never crosses a
page boundary. As a result, a page fault and subsequent oops no longer
occur. (BZ#1268203)

  * The NFS client was previously failing to detect a directory loop for some
NFS server directory structures. This failure could cause NFS inodes to
remain referenced after attempting to unmount the file system, leading to a
kernel crash. Loop checks have been added to VFS, which effectively
prevents this problem from occurring. (BZ#1272858)

  * Due to a race whereby the nfs_wb_pages_cancel() and
nfs_commit_release_pages() calls both removed a request from the nfs_inode
struct type, the kernel panicked with negative nfs_inode.npages count.
The provided upstream patch performs  ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:2636");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-December/021541.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.12.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
