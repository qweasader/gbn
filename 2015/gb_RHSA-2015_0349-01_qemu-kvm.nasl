# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871324");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-06 06:49:07 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-3640", "CVE-2014-7815", "CVE-2014-7840", "CVE-2014-8106");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for qemu-kvm RHSA-2015:0349-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-kvm'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
Linux on AMD64 and Intel 64 systems. The qemu-kvm packages provide the
user-space component for running virtual machines using KVM.

It was found that the Cirrus blit region checks were insufficient. A
privileged guest user could use this flaw to write outside of
VRAM-allocated buffer boundaries in the host's QEMU process address space
with attacker-provided data. (CVE-2014-8106)

An uninitialized data structure use flaw was found in the way the
set_pixel_format() function sanitized the value of bits_per_pixel. An
attacker able to access a guest's VNC console could use this flaw to crash
the guest. (CVE-2014-7815)

It was found that certain values that were read when loading RAM during
migration were not validated. A user able to alter the savevm data (either
on the disk or over the wire during migration) could use either of these
flaws to corrupt QEMU process memory on the (destination) host, which could
potentially result in arbitrary code execution on the host with the
privileges of the QEMU process. (CVE-2014-7840)

A NULL pointer dereference flaw was found in the way QEMU handled UDP
packets with a source port and address of 0 when QEMU's user networking was
in use. A local guest user could use this flaw to crash the guest.
(CVE-2014-3640)

Red Hat would like to thank James Spadaro of Cisco for reporting
CVE-2014-7815, and Xavier Mehrenberger and Stephane Duverger of Airbus for
reporting CVE-2014-3640. The CVE-2014-8106 issue was found by Paolo Bonzini
of Red Hat, and the CVE-2014-7840 issue was discovered by Michael S.
Tsirkin of Red Hat.

Bug fixes:

  * The KVM utility executed demanding routing update system calls every time
it performed an MSI vector mask/unmask operation. Consequently, guests
running legacy systems such as Red Hat Enterprise Linux 5 could, under
certain circumstances, experience significant slowdown. Now, the routing
system calls during mask/unmask operations are skipped, and the performance
of legacy guests is now more consistent. (BZ#1098976)

  * Due to a bug in the Internet Small Computer System Interface (iSCSI)
driver, a qemu-kvm process terminated unexpectedly with a segmentation
fault when the 'write same' command was executed in guest mode under the
iSCSI protocol. This update fixes the bug, and the 'write same' command now
functions in guest mode under iSCSI as intended. (BZ#1083413)

  * The QEMU command interface did not properly handle resizing of cache
memory during guest migration, causing QEMU to terminate unexpectedly with
a segmentation fault. This update ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"qemu-kvm on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"RHSA", value:"2015:0349-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00019.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"libcacard", rpm:"libcacard~1.5.3~86.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~1.5.3~86.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~1.5.3~86.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-common", rpm:"qemu-kvm-common~1.5.3~86.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-debuginfo", rpm:"qemu-kvm-debuginfo~1.5.3~86.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~1.5.3~86.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}