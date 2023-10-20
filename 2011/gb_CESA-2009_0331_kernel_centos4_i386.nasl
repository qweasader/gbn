# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-April/015804.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880926");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:0331");
  script_cve_id("CVE-2008-5700", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0322");
  script_name("CentOS Update for kernel CESA-2009:0331 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"kernel on CentOS 4");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update addresses the following security issues:

  * a buffer overflow was found in the Linux kernel Partial Reliable Stream
  Control Transmission Protocol (PR-SCTP) implementation. This could,
  potentially, lead to a denial of service if a Forward-TSN chunk is received
  with a large stream ID. (CVE-2009-0065, Important)

  * a memory leak was found in keyctl handling. A local, unprivileged user
  could use this flaw to deplete kernel memory, eventually leading to a
  denial of service. (CVE-2009-0031, Important)

  * a deficiency was found in the Remote BIOS Update (RBU) driver for Dell
  systems. This could allow a local, unprivileged user to cause a denial of
  service by reading zero bytes from the image_type or packet_size file in
  '/sys/devices/platform/dell_rbu/'. (CVE-2009-0322, Important)

  * a deficiency was found in the libATA implementation. This could,
  potentially, lead to a denial of service. Note: by default, '/dev/sg*'
  devices are accessible only to the root user. (CVE-2008-5700, Low)

  This update also fixes the following bugs:

  * when the hypervisor changed a page table entry (pte) mapping from
  read-only to writable via a make_writable hypercall, accessing the changed
  page immediately following the change caused a spurious page fault. When
  trying to install a para-virtualized Red Hat Enterprise Linux 4 guest on a
  Red Hat Enterprise Linux 5.3 dom0 host, this fault crashed the installer
  with a kernel backtrace. With this update, the 'spurious' page fault is
  handled properly. (BZ#483748)

  * net_rx_action could detect its cpu poll_list as non-empty, but have that
  same list reduced to empty by the poll_napi path. This resulted in garbage
  data being returned when net_rx_action calls list_entry, which subsequently
  resulted in several possible crash conditions. The race condition in the
  network code which caused this has been fixed. (BZ#475970, BZ#479681 &
  BZ#480741)

  * a misplaced memory barrier at unlock_buffer() could lead to a concurrent
  h_refcounter update which produced a reference counter leak and, later, a
  double free in ext3_xattr_release_block(). Consequent to the double free,
  ext3 reported an error

      ext3_free_blocks_sb: bit already cleared for block [block number]

  and mounted itself as read-only. With this update, the memory barrier is
  now placed before the buffer head lock bit, forcing the write order and
  preventing the double free. (BZ#476533)

  * when the iptables ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~78.0.17.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
