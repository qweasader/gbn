# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871668");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2016-10-05 05:42:58 +0200 (Wed, 05 Oct 2016)");
  script_cve_id("CVE-2016-4470", "CVE-2016-5829");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:16:00 +0000 (Tue, 17 Jan 2023)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for kernel RHSA-2016:2006-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * A flaw was found in the Linux kernel's keyring handling code, where in
key_reject_and_link() an uninitialized variable would eventually lead to
arbitrary free address which could allow attacker to use a use-after-free
style attack. (CVE-2016-4470, Important)

  * A heap-based buffer overflow vulnerability was found in the Linux
kernel's hiddev driver. This flaw could allow a local attacker to corrupt
kernel memory, possible privilege escalation or crashing the system.
(CVE-2016-5829, Moderate)

The CVE-2016-4470 issue was discovered by David Howells (Red Hat Inc.).

Bug Fix(es):

  * Previously, when two NFS shares with different security settings were
mounted, the I/O operations to the kerberos-authenticated mount caused the
RPC_CRED_KEY_EXPIRE_SOON parameter to be set, but the parameter was not
unset when performing the I/O operations on the sec=sys mount.
Consequently, writes to both NFS shares had the same parameters, regardless
of their security settings. This update fixes this problem by moving the
NO_CRKEY_TIMEOUT parameter to the auth- au_flags field. As a result, NFS
shares with different security settings are now handled as expected.
(BZ#1366962)

  * In some circumstances, resetting a Fibre Channel over Ethernet (FCoE)
interface could lead to a kernel panic, due to invalid information
extracted from the FCoE header. This update adds santiy checking to the cpu
number extracted from the FCoE header. This ensures that subsequent
operations address a valid cpu, and eliminates the kernel panic.
(BZ#1359036)

  * Prior to this update, the following problems occurred with the way GSF2
transitioned files and directories from the 'unlinked' state to the 'free'
state:

The numbers reported for the df and the du commands in some cases got out
of sync, which caused blocks in the file system to appear missing. The
blocks were not actually missing, but they were left in the 'unlinked'
state.

In some circumstances, GFS2 referenced a cluster lock that was already
deleted, which led to a kernel panic.

If an object was deleted and its space reused as a different object, GFS2
sometimes deleted the existing one, which caused file system corruption.

With this update, the transition from 'unlinked' to 'free' state has been
fixed. As a result, none of these three problems occur anymore.
(BZ#1359037)

  * Previously, the GFS2 file system in some cases became unresponsive due to
lock dependency ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:2006-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-October/msg00007.html");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf-debuginfo", rpm:"python-perf-debuginfo~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~642.6.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
