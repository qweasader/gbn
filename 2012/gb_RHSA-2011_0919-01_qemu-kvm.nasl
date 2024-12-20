# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00001.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870605");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-06 10:33:11 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-2212", "CVE-2011-2512");
  script_xref(name:"RHSA", value:"2011:0919-01");
  script_name("RedHat Update for qemu-kvm RHSA-2011:0919-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space component
  for running virtual machines using KVM.

  It was found that the virtio subsystem in qemu-kvm did not properly
  validate virtqueue in and out requests from the guest. A privileged guest
  user could use this flaw to trigger a buffer overflow, allowing them to
  crash the guest (denial of service) or, possibly, escalate their privileges
  on the host. (CVE-2011-2212)

  It was found that the virtio_queue_notify() function in qemu-kvm did not
  perform sufficient input validation on the value later used as an index
  into the array of virtqueues. An unprivileged guest user could use this
  flaw to crash the guest (denial of service) or, possibly, escalate their
  privileges on the host. (CVE-2011-2512)

  Red Hat would like to thank Nelson Elhage for reporting CVE-2011-2212.

  This update also fixes the following bug:

  * A bug was found in the way vhost (in qemu-kvm) set up mappings with the
  host kernel's vhost module. This could result in the host kernel's vhost
  module not having a complete view of a guest system's memory, if that guest
  had more than 4 GB of memory. Consequently, hot plugging a vhost-net
  network device and restarting the guest may have resulted in that device no
  longer working. (BZ#701771)

  All users of qemu-kvm should upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, shut down all running virtual machines. Once all virtual machines
  have shut down, start them again for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.160.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.160.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~0.12.1.2~2.160.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.160.el6_1.2", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
