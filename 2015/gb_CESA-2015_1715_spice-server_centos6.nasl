# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882275");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-09-04 08:14:52 +0200 (Fri, 04 Sep 2015)");
  script_cve_id("CVE-2015-3247");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for spice-server CESA-2015:1715 centos6");
  script_tag(name:"summary", value:"Check the version of spice-server");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Simple Protocol for Independent Computing Environments (SPICE) is a
remote display protocol for virtual environments. SPICE users can access a
virtualized desktop or server from the local system or any system with
network access to the server. SPICE is used in Red Hat Enterprise Linux for
viewing virtualized guests running on the Kernel-based Virtual Machine
(KVM) hypervisor or on Red Hat Enterprise Virtualization Hypervisors.

A race condition flaw, leading to a heap-based memory corruption, was found
in spice's worker_update_monitors_config() function, which runs under the
QEMU-KVM context on the host. A user in a guest could leverage this flaw to
crash the host QEMU-KVM process or, possibly, execute arbitrary code with
the privileges of the host QEMU-KVM process. (CVE-2015-3247)

This issue was discovered by Frediano Ziglio of Red Hat.

All spice-server users are advised to upgrade to this updated package,
which contains a backported patch to correct this issue.");
  script_tag(name:"affected", value:"spice-server on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"CESA", value:"2015:1715");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-September/021374.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"spice-server", rpm:"spice-server~0.12.4~12.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-server-devel", rpm:"spice-server-devel~0.12.4~12.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
