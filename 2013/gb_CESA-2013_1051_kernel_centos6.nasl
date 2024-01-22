# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881773");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2013-08-01 18:43:39 +0530 (Thu, 01 Aug 2013)");
  script_cve_id("CVE-2012-6548", "CVE-2013-0914", "CVE-2013-1848", "CVE-2013-2128",
                "CVE-2013-2634", "CVE-2013-2635", "CVE-2013-2852", "CVE-2013-3222",
                "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3301");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-03 15:09:00 +0000 (Mon, 03 Aug 2020)");
  script_name("CentOS Update for kernel CESA-2013:1051 centos6");

  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues:

  * A flaw was found in the tcp_read_sock() function in the Linux kernel's
IPv4 TCP/IP protocol suite implementation in the way socket buffers (skb)
were handled. A local, unprivileged user could trigger this issue via a
call to splice(), leading to a denial of service. (CVE-2013-2128,
Moderate)

  * Information leak flaws in the Linux kernel could allow a local,
unprivileged user to leak kernel memory to user-space. (CVE-2012-6548,
CVE-2013-2634, CVE-2013-2635, CVE-2013-3222, CVE-2013-3224, CVE-2013-3225,
Low)

  * An information leak was found in the Linux kernel's POSIX signals
implementation. A local, unprivileged user could use this flaw to bypass
the Address Space Layout Randomization (ASLR) security feature.
(CVE-2013-0914, Low)

  * A format string flaw was found in the ext3_msg() function in the Linux
kernel's ext3 file system implementation. A local user who is able to mount
an ext3 file system could use this flaw to cause a denial of service or,
potentially, escalate their privileges. (CVE-2013-1848, Low)

  * A format string flaw was found in the b43_do_request_fw() function in the
Linux kernel's b43 driver implementation. A local user who is able to
specify the 'fwpostfix' b43 module parameter could use this flaw to cause a
denial of service or, potentially, escalate their privileges.
(CVE-2013-2852, Low)

  * A NULL pointer dereference flaw was found in the Linux kernel's ftrace
and function tracer implementations. A local user who has the CAP_SYS_ADMIN
capability could use this flaw to cause a denial of service.
(CVE-2013-3301, Low)

Red Hat would like to thank Kees Cook for reporting CVE-2013-2852.

This update also fixes several bugs. Documentation for these changes will
be available shortly from the Technical Notes document linked to in the
References section.

Users should upgrade to these updated packages, which contain backported
patches to correct these issues. The system must be rebooted for this
update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2013:1051");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-July/019858.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.14.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
