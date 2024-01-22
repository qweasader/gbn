# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881955");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2014-06-23 15:31:16 +0530 (Mon, 23 Jun 2014)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-6378", "CVE-2014-0203", "CVE-2014-1737", "CVE-2014-1738",
                "CVE-2014-1874", "CVE-2014-2039", "CVE-2014-3153");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-08 16:25:00 +0000 (Mon, 08 Feb 2021)");
  script_name("CentOS Update for kernel CESA-2014:0771 centos6");

  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any
Linux operating system.

  * A flaw was found in the way the Linux kernel's futex subsystem handled
the requeuing of certain Priority Inheritance (PI) futexes. A local,
unprivileged user could use this flaw to escalate their privileges on the
system. (CVE-2014-3153, Important)

  * A flaw was found in the way the Linux kernel's floppy driver handled user
space provided data in certain error code paths while processing FDRAWCMD
IOCTL commands. A local user with write access to /dev/fdX could use this
flaw to free (using the kfree() function) arbitrary kernel memory.
(CVE-2014-1737, Important)

  * It was found that the Linux kernel's floppy driver leaked internal kernel
memory addresses to user space during the processing of the FDRAWCMD IOCTL
command. A local user with write access to /dev/fdX could use this flaw to
obtain information about the kernel heap arrangement. (CVE-2014-1738, Low)

Note: A local user with write access to /dev/fdX could use these two flaws
(CVE-2014-1737 in combination with CVE-2014-1738) to escalate their
privileges on the system.

  * It was discovered that the proc_ns_follow_link() function did not
properly return the LAST_BIND value in the last pathname component as is
expected for procfs symbolic links, which could lead to excessive freeing
of memory and consequent slab corruption. A local, unprivileged user could
use this flaw to crash the system. (CVE-2014-0203, Moderate)

  * A flaw was found in the way the Linux kernel handled exceptions when
user-space applications attempted to use the linkage stack. On IBM S/390
systems, a local, unprivileged user could use this flaw to crash the
system. (CVE-2014-2039, Moderate)

  * An invalid pointer dereference flaw was found in the Marvell 8xxx
Libertas WLAN (libertas) driver in the Linux kernel. A local user able to
write to a file that is provided by the libertas driver and located on the
debug file system (debugfs) could use this flaw to crash the system. Note:
The debugfs file system must be mounted locally to exploit this issue.
It is not mounted by default. (CVE-2013-6378, Low)

  * A denial of service flaw was discovered in the way the Linux kernel's
SELinux implementation handled files with an empty SELinux security
context. A local user who has the CAP_MAC_ADMIN capability could use this
flaw to crash the system. (CVE-2014-1874, Low)

Red Hat would like to thank Kees Cook of Google for reporting
CVE-2014-3153, Matthew Daley for reporting CVE-2014-1737 and CVE-2014-1738,
and Vladimir Davydov of Parallels for reporting CVE-2014-0203. Google
acknowledges Pinkie Pie as th ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0771");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-June/020379.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.20.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
