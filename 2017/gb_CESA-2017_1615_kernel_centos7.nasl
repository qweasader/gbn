# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882747");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-30 05:12:15 +0200 (Fri, 30 Jun 2017)");
  script_cve_id("CVE-2017-2583", "CVE-2017-6214", "CVE-2017-7477", "CVE-2017-7645", "CVE-2017-7895");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 16:13:00 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2017:1615 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

  * A flaw was found in the way Linux kernel allocates heap memory to build
the scattergather list from a fragment list(skb_shinfo(skb)- frag_list) in
the socket buffer(skb_buff). The heap overflow occurred if 'MAX_SKB_FRAGS +
1' parameter and 'NETIF_F_FRAGLIST' feature were used together. A
remote user or process could use this flaw to potentially escalate their
privilege on a system. (CVE-2017-7477, Important)

  * The NFS2/3 RPC client could send long arguments to the NFS server. These
encoded arguments are stored in an array of memory pages, and accessed
using pointer variables. Arbitrarily long arguments could make these
pointers point outside the array and cause an out-of-bounds memory access.
A remote user or program could use this flaw to crash the kernel (denial of
service). (CVE-2017-7645, Important)

  * The NFSv2 and NFSv3 server implementations in the Linux kernel through
4.10.13 lacked certain checks for the end of a buffer. A remote attacker
could trigger a pointer-arithmetic error or possibly cause other
unspecified impacts using crafted requests related to fs/nfsd/nfs3xdr.c and
fs/nfsd/nfsxdr.c. (CVE-2017-7895, Important)

  * The Linux kernel built with the Kernel-based Virtual Machine (CONFIG_KVM)
support was vulnerable to an incorrect segment selector(SS) value error.
The error could occur while loading values into the SS register in long
mode. A user or process inside a guest could use this flaw to crash the
guest, resulting in DoS or potentially escalate their privileges inside the
guest. (CVE-2017-2583, Moderate)

  * A flaw was found in the Linux kernel's handling of packets with the URG
flag. Applications using the splice() and tcp_splice_read() functionality
could allow a remote attacker to force the kernel to enter a condition in
which it could loop indefinitely. (CVE-2017-6214, Moderate)

Red Hat would like to thank Ari Kauppi for reporting CVE-2017-7895 and
Xiaohan Zhang (Huawei Inc.) for reporting CVE-2017-2583.

Bug Fix(es):

  * Previously, the reserved-pages counter (HugePages_Rsvd) was bigger than
the total-pages counter (HugePages_Total) in the /proc/meminfo file, and
HugePages_Rsvd underflowed. With this update, the HugeTLB feature of the
Linux kernel has been fixed, and HugePages_Rsvd underflow no longer occurs.
(BZ#1445184)

  * If a directory on a NFS client was modified while being listed, the NFS
client could restart the directory listing multiple times. Consequently,
the performance of listing the directory was sub-optimal. With this update,
the restarting of the di ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2017:1615");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-June/022489.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~514.26.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
