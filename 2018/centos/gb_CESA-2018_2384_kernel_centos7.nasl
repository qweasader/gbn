# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882935");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-08-15 06:18:41 +0200 (Wed, 15 Aug 2018)");
  script_cve_id("CVE-2017-13215", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-3693", "CVE-2018-5390", "CVE-2018-7566", "CVE-2018-10675");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 16:14:00 +0000 (Fri, 18 Sep 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2018:2384 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * Modern operating systems implement virtualization of physical memory to
efficiently use available system resources and provide inter-domain
protection through access control and isolation. The L1TF issue was found
in the way the x86 microprocessor designs have implemented speculative
execution of instructions (a commonly used performance optimisation) in
combination with handling of page-faults caused by terminated virtual to
physical address resolving process. As a result, an unprivileged attacker
could use this flaw to read privileged memory of the kernel or other
processes and/or cross guest/host boundaries to read host memory by
conducting targeted cache side-channel attacks. (CVE-2018-3620,
CVE-2018-3646)

  * An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions past bounds
check. The flaw relies on the presence of a precisely-defined instruction
sequence in the privileged code and the fact that memory writes occur to an
address which depends on the untrusted value. Such writes cause an update
into the microprocessor's data cache even for speculatively executed
instructions that never actually commit (retire). As a result, an
unprivileged attacker could use this flaw to influence speculative
execution and/or read privileged memory by conducting targeted cache
side-channel attacks. (CVE-2018-3693)

  * A flaw named SegmentSmack was found in the way the Linux kernel handled
specially crafted TCP packets. A remote attacker could use this flaw to
trigger time and calculation expensive calls to tcp_collapse_ofo_queue()
and tcp_prune_ofo_queue() functions by sending specially modified packets
within ongoing TCP sessions which could lead to a CPU saturation and hence
a denial of service on the system. Maintaining the denial of service
condition requires continuous two-way TCP sessions to a reachable open
port, thus the attacks cannot be performed using spoofed IP addresses.
(CVE-2018-5390)

  * kernel: crypto: privilege escalation in skcipher_recvmsg function
(CVE-2017-13215)

  * kernel: mm: use-after-free in do_get_mempolicy function allows local DoS
or other unspecified impact (CVE-2018-10675)

  * kernel: race condition in snd_seq_write() may lead to UAF or OOB access
(CVE-2018-7566)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Intel OSSIRT (Intel.com) for reporting ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2384");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-August/022984.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.11.6.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
