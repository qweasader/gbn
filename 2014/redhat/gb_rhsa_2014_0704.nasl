# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871189");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-07-04 16:48:48 +0530 (Fri, 04 Jul 2014)");
  script_cve_id("CVE-2014-2894");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for qemu-kvm RHSA-2014:0704-01");


  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
Linux on AMD64 and Intel 64 systems. The qemu-kvm packages provide a
user-space component to run virtual machines using KVM.

An out-of-bounds memory access flaw was found in the way QEMU's IDE device
driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process memory
on the host, which could potentially result in arbitrary code execution on
the host with the privileges of the QEMU process. (CVE-2014-2894)

This update also fixes the following bugs:

  * Prior to this update, a bug in the migration code caused the following
error on specific machine types: after a Red Hat Enterprise Linux 6.5 guest
was migrated from a Red Hat Enterprise Linux 6.5 host to a Red Hat
Enterprise Linux 7.0 host and then restarted, the boot failed and the guest
automatically restarted. Thus, the guest entered an endless loop. With this
update, the migration code has been fixed and the Red Hat Enterprise Linux
6.5 guests migrated in the aforementioned scenario now boot properly.
(BZ#1091322)

  * Due to a regression bug in the iSCSI driver, the qemu-kvm process
terminated unexpectedly with a segmentation fault when the 'write same'
command was executed in guest mode under the iSCSI protocol. This update
fixes the regression and the 'write same' command now functions in guest
mode under iSCSI as intended. (BZ#1090978)

  * Due to a mismatch in interrupt request (IRQ) routing, migration of a Red
Hat Enterprise Linux 6.5 guest from a Red Hat Enterprise Linux 6.5 host to
a Red Hat Enterprise Linux 7.0 host could produce a call trace.
This happened if memory ballooning and a Universal Host Control Interface
(UHCI) device were used at the same time on certain machine types.
With this patch, the IRQ routing mismatch has been amended and the
described migration now proceeds as expected. (BZ#1090981)

  * Previously, an internal error prevented KVM from executing a CPU hot plug
on a Red Hat Enterprise Linux 7 guest running on a Red Hat Enterprise Linux
7 host. This update addresses the internal error and CPU hot plugging in
the described scenario now functions correctly. (BZ#1094820)

All qemu-kvm users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, shut down all running virtual machines. Once all virtual machines
have shut down, start them again for this update to take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0704-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-June/msg00028.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~60.el7_0.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~1.5.3~60.el7_0.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~60.el7_0.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~60.el7_0.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~60.el7_0.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~1.5.3~60.el7_0.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~60.el7_0.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}