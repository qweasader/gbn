# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881832");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-12-17 11:56:12 +0530 (Tue, 17 Dec 2013)");
  script_cve_id("CVE-2013-2141", "CVE-2013-4470", "CVE-2013-6367", "CVE-2013-6368");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2013:1801 centos6");

  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

  * A flaw was found in the way the Linux kernel's TCP/IP protocol suite
implementation handled sending of certain UDP packets over sockets that
used the UDP_CORK option when the UDP Fragmentation Offload (UFO) feature
was enabled on the output device. A local, unprivileged user could use this
flaw to cause a denial of service or, potentially, escalate their
privileges on the system. (CVE-2013-4470, Important)

  * A divide-by-zero flaw was found in the apic_get_tmcct() function in KVM's
Local Advanced Programmable Interrupt Controller (LAPIC) implementation.
A privileged guest user could use this flaw to crash the host.
(CVE-2013-6367, Important)

  * A memory corruption flaw was discovered in the way KVM handled virtual
APIC accesses that crossed a page boundary. A local, unprivileged user
could use this flaw to crash the system or, potentially, escalate their
privileges on the system. (CVE-2013-6368, Important)

  * An information leak flaw in the Linux kernel could allow a local,
unprivileged user to leak kernel memory to user space. (CVE-2013-2141, Low)

Red Hat would like to thank Hannes Frederic Sowa for reporting
CVE-2013-4470, and Andrew Honig of Google for reporting CVE-2013-6367 and
CVE-2013-6368.

This update also fixes several bugs and adds two enhancements.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add these
enhancements. The system must be rebooted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1801");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-December/020074.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~431.1.2.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}