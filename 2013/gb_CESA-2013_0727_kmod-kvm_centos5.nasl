# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881709");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-04-15 10:12:35 +0530 (Mon, 15 Apr 2013)");
  script_cve_id("CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kmod-kvm CESA-2013:0727 centos5");

  script_xref(name:"CESA", value:"2013:0727");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-April/019683.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmod-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kmod-kvm on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module built for
  the standard Red Hat Enterprise Linux kernel.

  A flaw was found in the way KVM handled guest time updates when the buffer
  the guest registered by writing to the MSR_KVM_SYSTEM_TIME machine state
  register (MSR) crossed a page boundary. A privileged guest user could use
  this flaw to crash the host or, potentially, escalate their privileges,
  allowing them to execute arbitrary code at the host kernel level.
  (CVE-2013-1796)

  A potential use-after-free flaw was found in the way KVM handled guest time
  updates when the GPA (guest physical address) the guest registered by
  writing to the MSR_KVM_SYSTEM_TIME machine state register (MSR) fell into a
  movable or removable memory region of the hosting user-space process (by
  default, QEMU-KVM) on the host. If that memory region is deregistered from
  KVM using KVM_SET_USER_MEMORY_REGION and the allocated virtual memory
  reused, a privileged guest user could potentially use this flaw to
  escalate their privileges on the host. (CVE-2013-1797)

  A flaw was found in the way KVM emulated IOAPIC (I/O Advanced Programmable
  Interrupt Controller). A missing validation check in the
  ioapic_read_indirect() function could allow a privileged guest user to
  crash the host, or read a substantial portion of host kernel memory.
  (CVE-2013-1798)

  Red Hat would like to thank Andrew Honig of Google for reporting all of
  these issues.

  All users of kvm are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. Note that the procedure
  in the Solution section must be performed before this update will take
  effect.");
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

  if ((res = isrpmvuln(pkg:"kmod-kvm", rpm:"kmod-kvm~83~262.el5.centos.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kmod-kvm-debug", rpm:"kmod-kvm-debug~83~262.el5.centos.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm", rpm:"kvm~83~262.el5.centos.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-qemu-img", rpm:"kvm-qemu-img~83~262.el5.centos.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kvm-tools", rpm:"kvm-tools~83~262.el5.centos.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
