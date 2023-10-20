# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017457.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881442");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:52:43 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-1146");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2011:0391");
  script_name("CentOS Update for libvirt CESA-2011:0391 centos5 x86_64");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libvirt on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remotely managing virtualized systems.

  It was found that several libvirt API calls did not honor the read-only
  permission for connections. A local attacker able to establish a read-only
  connection to libvirtd on a server could use this flaw to execute commands
  that should be restricted to read-write connections, possibly leading to a
  denial of service or privilege escalation. (CVE-2011-1146)

  Note: Previously, using rpmbuild without the '--define 'rhel 5'' option to
  build the libvirt source RPM on Red Hat Enterprise Linux 5 failed with a
  'Failed build dependencies' error for the device-mapper-devel package, as
  this -devel sub-package is not available on Red Hat Enterprise Linux 5.
  With this update, the -devel sub-package is no longer checked by default as
  a dependency when building on Red Hat Enterprise Linux 5, allowing the
  libvirt source RPM to build as expected.

  All libvirt users are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing the
  updated packages, libvirtd must be restarted ('service libvirtd restart')
  for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~15.el5_6.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~15.el5_6.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~15.el5_6.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
