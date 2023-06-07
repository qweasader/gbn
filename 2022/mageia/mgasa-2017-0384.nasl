# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0384");
  script_cve_id("CVE-2017-1000252", "CVE-2017-12153", "CVE-2017-12154", "CVE-2017-14106", "CVE-2017-14156", "CVE-2017-14489", "CVE-2017-14497", "CVE-2017-14991", "CVE-2017-7518", "CVE-2017-7558");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 15:48:00 +0000 (Thu, 19 Jan 2023)");

  script_name("Mageia: Security Advisory (MGASA-2017-0384)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0384");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0384.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21851");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.51");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.52");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.53");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.54");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.55");
  script_xref(name:"URL", value:"https://cdn.kernel.org/pub/linux/kernel/v4.x/ChangeLog-4.9.56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-tmb' package(s) announced via the MGASA-2017-0384 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-tmb update is based on upstream 4.9.56 and fixes at least the
following security issues:

A flaw was found in the way the Linux KVM module processed the trap flag(TF)
bit in EFLAGS during emulation of the syscall instruction, which leads to a
debug exception(#DB) being raised in the guest stack. A user/process inside
a guest could use this flaw to potentially escalate their privileges inside
the guest (CVE-2017-7518).

A kernel data leak due to an out-of-bound read was found in the Linux kernel
in inet_diag_msg_sctp{,l}addr_fill() and sctp_get_sctp_info() functions
present since version 4.7-rc1 through version 4.13. A data leak happens when
these functions fill in sockaddr data structures used to export socket's
diagnostic information. As a result, up to 100 bytes of the slab data could
be leaked to a userspace (CVE-2017-7558).

A security flaw was discovered in nl80211_set_rekey_data() function in the
Linux kernel since v3.1-rc1 through v4.13. This function does not check
whether the required attributes are present in a netlink request. This
request can be issued by a user with CAP_NET_ADMIN privilege and may result
in NULL dereference and a system crash (CVE-2017-12153).

Linux kernel built with the KVM visualization support (CONFIG_KVM), with
nested visualization (nVMX) feature enabled (nested=1), is vulnerable to a
crash due to disabled external interrupts. As L2 guest could acce s (r/w)
hardware CR8 register of the host(L0). In a nested visualization setup,
L2 guest user could use this flaw to potentially crash the host(L0)
resulting in DoS (CVE-2017-12154).

The tcp_disconnect function in net/ipv4/tcp.c in the Linux kernel before
4.12 allows local users to cause a denial of service (__tcp_select_window
divide-by-zero error and system crash) by triggering a disconnect within a
certain tcp_recvmsg code path (CVE-2017-14106).

The atyfb_ioctl function in drivers/video/fbdev/aty/atyfb_base.c in the
Linux kernel through 4.12.10 does not initialize a certain data structure,
which allows local users to obtain sensitive information from kernel stack
memory by reading locations associated with padding bytes (CVE-2017-14156).

It was found that the iscsi_if_rx() function in scsi_transport_iscsi.c in
the Linux kernel since v2.6.24-rc1 through 4.13.2 allows local users to
cause a denial of service (a system panic) by making a number of certain
syscalls by leveraging incorrect length validation in the kernel code
(CVE-2017-14489).

The sg_ioctl function in drivers/scsi/sg.c in the Linux kernel before 4.13.4
allows local users to obtain sensitive information from uninitialized kernel
heap-memory locations via an SG_GET_REQUEST_TABLE ioctl call for /dev/sg0
(CVE-2017-14991).

The tpacket_rcv() function in 'net/packet/af_packet.c' file in the Linux
kernel before 4.13 mishandles vnet headers, which might allow local users
to cause a denial of service (buffer overflow, ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel-tmb' package(s) on Mageia 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb", rpm:"kernel-tmb~4.9.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-4.9.56-1.mga6", rpm:"kernel-tmb-desktop-4.9.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-4.9.56-1.mga6", rpm:"kernel-tmb-desktop-devel-4.9.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-devel-latest", rpm:"kernel-tmb-desktop-devel-latest~4.9.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-desktop-latest", rpm:"kernel-tmb-desktop-latest~4.9.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-4.9.56-1.mga6", rpm:"kernel-tmb-source-4.9.56-1.mga6~1~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tmb-source-latest", rpm:"kernel-tmb-source-latest~4.9.56~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
