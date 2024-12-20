# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871644");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-08-04 16:27:46 +0530 (Thu, 04 Aug 2016)");
  script_cve_id("CVE-2015-8660", "CVE-2016-2143", "CVE-2016-4470");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-07 12:44:00 +0000 (Wed, 07 Jun 2023)");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for kernel RHSA-2016:1539-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

These updated kernel packages include several security issues and numerous
bug fixes, some of which you can see below. Space precludes documenting
all of these bug fixes in this advisory. To see the complete list of bug
fixes, users are directed to the related Knowledge Article.

Security Fix(es):

  * A flaw was found in the Linux kernel's keyring handling code, where in
key_reject_and_link() an uninitialised variable would eventually lead to
arbitrary free address which could allow attacker to use a use-after-free
style attack. (CVE-2016-4470, Important)

  * The ovl_setattr function in fs/overlayfs/inode.c in the Linux kernel
through 4.3.3 attempts to merge distinct setattr operations, which allows
local users to bypass intended access restrictions and modify the
attributes of arbitrary overlay files via a crafted application.
(CVE-2015-8660, Moderate)

  * It was reported that on s390x, the fork of a process with four page table
levels will cause memory corruption with a variety of symptoms. All
processes are created with three level page table and a limit of 4TB for
the address space. If the parent process has four page table levels with a
limit of 8PB, the function that duplicates the address space will try to
copy memory areas outside of the address space limit for the child process.
(CVE-2016-2143, Moderate)

Red Hat would like to thank Nathan Williams for reporting CVE-2015-8660.
The CVE-2016-4470 issue was discovered by David Howells (Red Hat Inc.).

Bug Fix(es):

  * The glibc headers and the Linux headers share certain definitions of
key structures that are required to be defined in kernel and in userspace.
In some instances both userspace and sanitized kernel headers have to be
included in order to get the structure definitions required by the user
program. Unfortunately because the glibc and Linux headers don't
coordinate this can result in compilation errors. The glibc headers have
therefore been fixed to coordinate with Linux UAPI-based headers. With
the header coordination compilation errors no longer occur. (BZ#1331285)

  * When running the TCP/IPv6 traffic over the mlx4_en networking interface
on the big endian architectures, call traces reporting about a 'hw csum
failure' could occur. With this update, the mlx4_en driver has been fixed
by correction of the checksum calculation for the big endian
architectures. As a result, the call trace error no longer app ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux
  Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"RHSA", value:"2016:1539-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-August/msg00004.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  script_xref(name:"URL", value:"https://access.redhat.com/articles/2460971");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf-debuginfo", rpm:"python-perf-debuginfo~3.10.0~327.28.2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
