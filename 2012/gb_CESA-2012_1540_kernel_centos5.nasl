# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-December/019024.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881547");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-12-06 10:24:49 +0530 (Thu, 06 Dec 2012)");
  script_cve_id("CVE-2012-2372", "CVE-2012-3552", "CVE-2012-4508", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-5513");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 11:33:00 +0000 (Fri, 31 Jul 2020)");
  script_xref(name:"CESA", value:"2012:1540");
  script_name("CentOS Update for kernel CESA-2012:1540 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"These packages contain the Linux kernel.

  Security fixes:

  * A race condition in the way asynchronous I/O and fallocate() interacted
  when using ext4 could allow a local, unprivileged user to obtain random
  data from a deleted file. (CVE-2012-4508, Important)

  * A flaw in the way the Xen hypervisor implementation range checked guest
  provided addresses in the XENMEM_exchange hypercall could allow a
  malicious, para-virtualized guest administrator to crash the hypervisor or,
  potentially, escalate their privileges, allowing them to execute arbitrary
  code at the hypervisor level. (CVE-2012-5513, Important)

  * A flaw in the Reliable Datagram Sockets (RDS) protocol implementation
  could allow a local, unprivileged user to cause a denial of service.
  (CVE-2012-2372, Moderate)

  * A race condition in the way access to inet->opt ip_options was
  synchronized in the Linux kernel's TCP/IP protocol suite implementation.
  Depending on the network facing applications running on the system, a
  remote attacker could possibly trigger this flaw to cause a denial of
  service. A local, unprivileged user could use this flaw to cause a denial
  of service regardless of the applications the system runs. (CVE-2012-3552,
  Moderate)

  * The Xen hypervisor implementation did not properly restrict the period
  values used to initialize per VCPU periodic timers. A privileged guest user
  could cause an infinite loop on the physical CPU. If the watchdog were
  enabled, it would detect said loop and panic the host system.
  (CVE-2012-4535, Moderate)

  * A flaw in the way the Xen hypervisor implementation handled
  set_p2m_entry() error conditions could allow a privileged,
  fully-virtualized guest user to crash the hypervisor. (CVE-2012-4537,
  Moderate)

  Red Hat would like to thank Theodore Ts'o for reporting CVE-2012-4508, the
  Xen project for reporting CVE-2012-5513, CVE-2012-4535, and CVE-2012-4537,
  and Hafid Lin for reporting CVE-2012-3552. Upstream acknowledges Dmitry
  Monakhov as the original reporter of CVE-2012-4508. CVE-2012-2372 was
  discovered by Li Honggang of Red Hat.

  Bug fixes:

  * Previously, the interrupt handlers of the qla2xxx driver could clear
  pending interrupts right after the IRQ lines were attached during system
  start-up. Consequently, the kernel could miss the interrupt that reported
  completion of the link initialization, and the qla2xxx driver then failed
  to detect all attached LUNs. With this update, the qla2xxx driver has been
  modified to no longer clear interrupt bits after attaching the IRQ lines.
  The driver now correctly det ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~308.24.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
