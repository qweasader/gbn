# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882114");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-01-30 05:20:12 +0100 (Fri, 30 Jan 2015)");
  script_cve_id("CVE-2014-4171", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-7145", "CVE-2014-7822", "CVE-2014-7841");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2015:0102 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

  * A flaw was found in the way the Linux kernel's SCTP implementation
validated INIT chunks when performing Address Configuration Change
(ASCONF). A remote attacker could use this flaw to crash the system by
sending a specially crafted SCTP packet to trigger a NULL pointer
dereference on the system. (CVE-2014-7841, Important)

  * A race condition flaw was found in the way the Linux kernel's mmap(2),
madvise(2), and fallocate(2) system calls interacted with each other while
operating on virtual memory file system files. A local user could use this
flaw to cause a denial of service. (CVE-2014-4171, Moderate)

  * A NULL pointer dereference flaw was found in the way the Linux kernel's
Common Internet File System (CIFS) implementation handled mounting of file
system shares. A remote attacker could use this flaw to crash a client
system that would mount a file system share from a malicious server.
(CVE-2014-7145, Moderate)

  * A flaw was found in the way the Linux kernel's splice() system call
validated its parameters. On certain file systems, a local, unprivileged
user could use this flaw to write past the maximum file size, and thus
crash the system. (CVE-2014-7822, Moderate)

  * It was found that the parse_rock_ridge_inode_internal() function of the
Linux kernel's ISOFS implementation did not correctly check relocated
directories when processing Rock Ridge child link (CL) tags. An attacker
with physical access to the system could use a specially crafted ISO image
to crash the system or, potentially, escalate their privileges on the
system. (CVE-2014-5471, CVE-2014-5472, Low)

Red Hat would like to thank Akira Fujita of NEC for reporting the
CVE-2014-7822 issue. The CVE-2014-7841 issue was discovered by Liu Wei of
Red Hat.

This update also fixes the following bugs:

  * Previously, a kernel panic could occur if a process reading from a locked
NFS file was killed and the lock was not released properly before the read
operations finished. Consequently, the system crashed. The code handling
file locks has been fixed, and instead of halting, the system now emits a
warning about the unreleased lock. (BZ#1172266)

  * A race condition in the command abort handling logic of the ipr device
driver could cause the kernel to panic when the driver received a response
to an abort command prior to receiving other responses to the aborted
command due to the support for multiple interrupts. With this update, the
abort handler waits for the aborted command's responses first before
completing an abort operation. (BZ#1162734)

  * Previously, a ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:0102");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-January/020916.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~123.20.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}