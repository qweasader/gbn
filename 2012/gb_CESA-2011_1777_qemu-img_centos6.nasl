# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-December/018350.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881330");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:25:12 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-4111");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:1777");
  script_name("CentOS Update for qemu-img CESA-2011:1777 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu-img'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"qemu-img on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"KVM (Kernel-based Virtual Machine) is a full virtualization solution for
  Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space component
  for running virtual machines using KVM.

  A flaw was found in the way qemu-kvm handled VSC_ATR messages when a guest
  was configured for a CCID (Chip/Smart Card Interface Devices) USB smart
  card reader in passthrough mode. An attacker able to connect to the port on
  the host being used for such a device could use this flaw to crash the
  qemu-kvm process on the host or, possibly, escalate their privileges on the
  host. (CVE-2011-4111)

  All users of qemu-kvm should upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, shut down all running virtual machines. Once all virtual machines
  have shut down, start them again for this update to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"qemu-img", rpm:"qemu-img~0.12.1.2~2.209.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~0.12.1.2~2.209.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm-tools", rpm:"qemu-kvm-tools~0.12.1.2~2.209.el6_2.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
