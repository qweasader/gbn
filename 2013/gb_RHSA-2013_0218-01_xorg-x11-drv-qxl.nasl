# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00065.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870898");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-04 09:53:58 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2013-0241");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"RHSA", value:"2013:0218-01");
  script_name("RedHat Update for xorg-x11-drv-qxl RHSA-2013:0218-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-drv-qxl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"xorg-x11-drv-qxl on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The xorg-x11-drv-qxl package provides an X11 video driver for the QEMU QXL
  video accelerator. This driver makes it possible to use Red Hat Enterprise
  Linux 6 as a guest operating system under the KVM kernel module and the
  QEMU multi-platform emulator, using the SPICE protocol.

  A flaw was found in the way the host's qemu-kvm qxl driver and the guest's
  X.Org qxl driver interacted when a SPICE connection terminated. A user able
  to initiate a SPICE connection to a guest could use this flaw to make the
  guest temporarily unavailable or, potentially (if the sysctl
  kernel.softlockup_panic variable was set to '1' in the guest), crash the
  guest. (CVE-2013-0241)

  All users of xorg-x11-drv-qxl are advised to upgrade to this updated
  package, which contains a backported patch to correct this issue. All
  running X.Org server instances using the qxl driver must be restarted for
  this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"xorg-x11-drv-qxl", rpm:"xorg-x11-drv-qxl~0.0.14~14.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xorg-x11-drv-qxl-debuginfo", rpm:"xorg-x11-drv-qxl-debuginfo~0.0.14~14.el6_3", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
