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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0215");
  script_cve_id("CVE-2013-0231", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2850", "CVE-2013-2852");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2013-0215)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0215");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0215.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=10699");
  script_xref(name:"URL", value:"http://kernel.ubuntu.com/git?p=ubuntu/linux.git;h=refs/heads/linux-3.8.y;a=shortlog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel-rt' package(s) announced via the MGASA-2013-0215 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This kernel-rt update provides the extended stable 3.8.13.4 kernel and
fixes the following security issues:

The pciback_enable_msi function in the PCI backend driver
(drivers/xen/pciback/conf_space_capability_msi.c) in Xen for the Linux
kernel 2.6.18 and 3.8 allows guest OS users with PCI device access to
cause a denial of service via a large number of kernel log messages.
(CVE-2013-0231 / XSA-43)

ipv6: ip6_sk_dst_check() must not assume ipv6 dst
It's possible to use AF_INET6 sockets and to connect to an IPv4
destination. After this, socket dst cache is a pointer to a rtable,
not rt6_info. This bug can be exploited by local non-root users
to trigger various corruptions/crashes (CVE-2013-2232)

af_key: fix info leaks in notify messages
key_notify_sa_flush() and key_notify_policy_flush() miss to
initialize the sadb_msg_reserved member of the broadcasted message
and thereby leak 2 bytes of heap memory to listeners (CVE-2013-2234)

af_key: initialize satype in key_notify_policy_flush()
key_notify_policy_flush() miss to nitialize the sadb_msg_satype member
of the broadcasted message and thereby leak heap memory to listeners
(CVE-2013-2237)

Heap-based buffer overflow in the iscsi_add_notunderstood_response function
in drivers/target/iscsi/iscsi_target_parameters.c in the iSCSI target
subsystem in the Linux kernel through 3.9.4 allows remote attackers to
cause a denial of service (memory corruption and OOPS) or possibly execute
arbitrary code via a long key that is not properly handled during
construction of an error-response packet.
A reproduction case requires patching open-iscsi to send overly large
keys. Performing discovery in a loop will Oops the remote server.
(CVE-2013-2850)

Format string vulnerability in the b43_request_firmware function in
drivers/net/wireless/b43/main.c in the Broadcom B43 wireless driver in
the Linux kernel through 3.9.4 allows local users to gain privileges by
leveraging root access and including format string specifiers in an
fwpostfix modprobe parameter, leading to improper construction of an
error message. (CVE-2013-2852)

Other fixes:
- Fix up alx AR8161 breakage (mga #10079)
- md/raid10: fix two bugs affecting RAID10 reshape
- perf: Disable monitoring on setuid processes for regular users
- netfilter: nf_conntrack_ipv6: Plug sk_buff leak in fragment handling
- enable X86_X2APIC, X86_REROUTE_FOR_BROKEN_BOOT_IRQS, FHANDLE
- disable COMPAT_VDSO (not needed since glibc-2.3.3)

The -rt patch has been updated to -rt14

For other fixes in the extended stable update, see the referenced shortlog");

  script_tag(name:"affected", value:"'kernel-rt' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-3.8.13.4-0.rt14.2.mga3", rpm:"kernel-rt-3.8.13.4-0.rt14.2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt", rpm:"kernel-rt~3.8.13.4~0.rt14.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-3.8.13.4-0.rt14.2.mga3", rpm:"kernel-rt-devel-3.8.13.4-0.rt14.2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-devel-latest", rpm:"kernel-rt-devel-latest~3.8.13.4~0.rt14.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-doc", rpm:"kernel-rt-doc~3.8.13.4~0.rt14.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-latest", rpm:"kernel-rt-latest~3.8.13.4~0.rt14.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-3.8.13.4-0.rt14.2.mga3", rpm:"kernel-rt-source-3.8.13.4-0.rt14.2.mga3~1~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-rt-source-latest", rpm:"kernel-rt-source-latest~3.8.13.4~0.rt14.2.mga3", rls:"MAGEIA3"))) {
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
