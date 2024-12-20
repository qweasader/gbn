# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-September/017031.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880648");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 16:03:00 +0000 (Fri, 14 Aug 2020)");
  script_xref(name:"CESA", value:"2010:0723");
  script_cve_id("CVE-2010-1083", "CVE-2010-2492", "CVE-2010-2798", "CVE-2010-2938", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-3015");
  script_name("CentOS Update for kernel CESA-2010:0723 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A buffer overflow flaw was found in the ecryptfs_uid_hash() function in
  the Linux kernel eCryptfs implementation. On systems that have the eCryptfs
  netlink transport (Red Hat Enterprise Linux 5 does) or where the
  &'/dev/ecryptfs' file has world writable permissions (which it does not, by
  default, on Red Hat Enterprise Linux 5), a local, unprivileged user could
  use this flaw to cause a denial of service or possibly escalate their
  privileges. (CVE-2010-2492, Important)

  * A miscalculation of the size of the free space of the initial directory
  entry in a directory leaf block was found in the Linux kernel Global File
  System 2 (GFS2) implementation. A local, unprivileged user with write
  access to a GFS2-mounted file system could perform a rename operation on
  that file system to trigger a NULL pointer dereference, possibly resulting
  in a denial of service or privilege escalation. (CVE-2010-2798, Important)

  * A flaw was found in the Xen hypervisor implementation when running a
  system that has an Intel CPU without Extended Page Tables (EPT) support.
  While attempting to dump information about a crashing fully-virtualized
  guest, the flaw could cause the hypervisor to crash the host as well. A
  user with permissions to configure a fully-virtualized guest system could
  use this flaw to crash the host. (CVE-2010-2938, Moderate)

  * Information leak flaws were found in the Linux kernel's Traffic Control
  Unit implementation. A local attacker could use these flaws to cause the
  kernel to leak kernel memory to user-space, possibly leading to the
  disclosure of sensitive information. (CVE-2010-2942, Moderate)

  * A flaw was found in the Linux kernel's XFS file system implementation.
  The file handle lookup could return an invalid inode as valid. If an XFS
  file system was mounted via NFS (Network File System), a local attacker
  could access stale data or overwrite existing data that reused the inodes.
  (CVE-2010-2943, Moderate)

  * An integer overflow flaw was found in the extent range checking code in
  the Linux kernel's ext4 file system implementation. A local, unprivileged
  user with write access to an ext4-mounted file system could trigger this
  flaw by writing to a file at a very large file offset, resulting in a local
  denial of service. (CVE-2010-3015, Moderate)

  * An information leak flaw was found in the Linux kernel's USB
  implementation. Certain USB errors could result in an uninitia ...

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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.17.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
