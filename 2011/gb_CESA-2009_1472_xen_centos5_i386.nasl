# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016286.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880684");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1472");
  script_cve_id("CVE-2009-3525");
  script_name("CentOS Update for xen CESA-2009:1472 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"xen on CentOS 5");
  script_tag(name:"insight", value:"Xen is an open source virtualization framework. Virtualization allows users
  to run guest operating systems in virtual machines on top of a host
  operating system.

  The pyGrub boot loader did not honor the 'password' option in the grub.conf
  file for para-virtualized guests. Users with access to a guest's console
  could use this flaw to bypass intended access restrictions and boot the
  guest with arbitrary kernel boot options, allowing them to get root
  privileges in the guest's operating system. With this update, pyGrub
  correctly honors the 'password' option in grub.conf for para-virtualized
  guests. (CVE-2009-3525)

  This update also fixes the following bugs:

  * rebooting para-virtualized guests sometimes caused those guests to crash
  due to a race condition in the xend node control daemon. This update fixes
  this race condition so that rebooting guests no longer potentially causes
  them to crash and fail to reboot. (BZ#525141)

  * due to a race condition in the xend daemon, a guest could disappear from
  the list of running guests following a reboot, even though the guest
  rebooted successfully and was running. This update fixes this race
  condition so that guests always reappear in the guest list following a
  reboot. (BZ#525143)

  * attempting to use PCI pass-through to para-virtualized guests on certain
  kernels failed with a 'Function not implemented' error message. As a
  result, users requiring PCI pass-through on para-virtualized guests were
  not able to update the xen packages without also updating the kernel and
  thus requiring a reboot. These updated packages enable PCI pass-through for
  para-virtualized guests so that users do not need to upgrade the kernel in
  order to take advantage of PCI pass-through functionality. (BZ#525149)

  All Xen users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the xend service must be restarted for this update to take
  effect.");
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

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~3.0.3~94.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~3.0.3~94.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~3.0.3~94.el5_4.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
