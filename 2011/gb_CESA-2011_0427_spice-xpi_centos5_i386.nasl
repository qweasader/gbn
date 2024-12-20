# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-April/017303.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880494");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2011:0427");
  script_cve_id("CVE-2011-1179");
  script_name("CentOS Update for spice-xpi CESA-2011:0427 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-xpi'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"spice-xpi on CentOS 5");
  script_tag(name:"insight", value:"The Simple Protocol for Independent Computing Environments (SPICE) is a
  remote display protocol used in Red Hat Enterprise Linux for viewing
  virtualized guests running on the Kernel-based Virtual Machine (KVM)
  hypervisor, or on Red Hat Enterprise Virtualization Hypervisor.

  The spice-xpi package provides a plug-in that allows the SPICE client to
  run from within Mozilla Firefox.

  An uninitialized pointer use flaw was found in the SPICE Firefox plug-in.
  If a user were tricked into visiting a malicious web page with Firefox
  while the SPICE plug-in was enabled, it could cause Firefox to crash or,
  possibly, execute arbitrary code with the privileges of the user running
  Firefox. (CVE-2011-1179)

  Users of spice-xpi should upgrade to this updated package, which contains a
  backported patch to correct this issue. After installing the update,
  Firefox must be restarted for the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"spice-xpi", rpm:"spice-xpi~2.2~2.3.el5_6.1", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
