# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871606");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-05-06 15:29:35 +0530 (Fri, 06 May 2016)");
  script_cve_id("CVE-2015-5157", "CVE-2015-8767");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-30 16:53:00 +0000 (Thu, 30 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for kernel RHSA-2016:0715-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * A flaw was found in the way the Linux kernel handled IRET faults during
the processing of NMIs. An unprivileged, local user could use this flaw to
crash the system or, potentially (although highly unlikely), escalate their
privileges on the system. (CVE-2015-5157, Moderate)

  * A race condition flaw was found in the way the Linux kernel's SCTP
implementation handled sctp_accept() during the processing of heartbeat
timeout events. A remote attacker could use this flaw to prevent further
connections to be accepted by the SCTP server running on the system,
resulting in a denial of service. (CVE-2015-8767, Moderate)

Bug Fix(es):

  * When the nvme driver held the queue lock for too long, for example during
DMA mapping, a lockup occurred leading to nvme hard-lockup panic. This
update fixes the underlying source code, and nvme now works as
expected.(BZ#1314209)

  * Due to a regression, a Unix domain datagram socket could come to a
deadlock when sending a datagram to itself. The provided patch adds another
'sk' check to the unix_dgram_sendmsg() function, and the aforementioned
deadlock no longer occurs. (BZ#1315696)

  * Previously, writing a large file using direct I/O in 16 MB chunks
sometimes caused a pathological allocation pattern where 16 MB chunks of
large free extent were allocated to a file in reversed order. The provided
patch avoids the backward allocation, and writing a large file using direct
I/O now proceeds successfully. (BZ#1320031)

  * MD RAID1 devices that repeatedly became hot removed and re-added could
become mismatched due to a race condition. This caused them to return stale
data, leading to data corruption. The provided set of patches fixes this
bug, and hot removals and re-additions of md devices now work as expected.
(BZ#1320863)

  * A couple of previous fixes caused a deadlock on the 'rq' lock leading to
a kernel panic on CPU 0. The provided set of patches reverts the relevant
commits, thus preventing the panic from occurring. (BZ#1326043)

Enhancement(s):

  * VLAN support has been updated to integrate some of the latest upstream
features. This update also makes sure that Null pointer crashes related to
VLAN support in bonding mode no longer occur and that tag stripping and
insertion work as expected. (BZ#1315706)

  * This update adds additional model numbers for Broadwell to perf.
(BZ#1320035)");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:0715-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-May/msg00007.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf-debuginfo", rpm:"python-perf-debuginfo~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~573.26.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
