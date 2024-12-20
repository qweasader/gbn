# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-January/015535.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880804");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:0003");
  script_cve_id("CVE-2008-4405", "CVE-2008-4993");
  script_name("CentOS Update for xen CESA-2009:0003 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"xen on CentOS 5");
  script_tag(name:"insight", value:"The xen packages contain the Xen tools and management daemons needed to
  manage virtual machines running on Red Hat Enterprise Linux.

  Xen was found to allow unprivileged DomU domains to overwrite xenstore
  values which should only be changeable by the privileged Dom0 domain. An
  attacker controlling a DomU domain could, potentially, use this flaw to
  kill arbitrary processes in Dom0 or trick a Dom0 user into accessing the
  text console of a different domain running on the same host. This update
  makes certain parts of the xenstore tree read-only to the unprivileged DomU
  domains. (CVE-2008-4405)

  It was discovered that the qemu-dm.debug script created a temporary file in
  /tmp in an insecure way. A local attacker in Dom0 could, potentially, use
  this flaw to overwrite arbitrary files via a symlink attack. Note: This
  script is not needed in production deployments and therefore was removed
  and is not shipped with updated xen packages. (CVE-2008-4993)

  This update also fixes the following bug:

  * xen calculates its running time by adding the hypervisor's up-time to the
  hypervisor's boot-time record. In live migrations of para-virtualized
  guests, however, the guest would over-write the new hypervisor's boot-time
  record with the boot-time of the previous hypervisor. This caused
  time-dependent processes on the guests to fail (for example, crond would
  fail to start cron jobs). With this update, the new hypervisor's boot-time
  record is no longer over-written during live migrations.

  All xen users are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. The Xen host must be
  restarted for the update to take effect.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~64.el5_2.9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.0.3~64.el5_2.9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~64.el5_2.9", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
