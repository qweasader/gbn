# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"affected", value:"libvirt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remote management of virtualized
  systems.

  It was discovered that libvirt made certain invalid assumptions about
  dnsmasq's command line options when setting up DNS masquerading for virtual
  machines, resulting in dnsmasq incorrectly processing network packets from
  network interfaces that were intended to be prohibited. This update
  includes the changes necessary to call dnsmasq with a new command line
  option, which was introduced to dnsmasq via RHSA-2013:0277. (CVE-2012-3411)

  In order for libvirt to be able to make use of the new command line option
  (--bind-dynamic), updated dnsmasq packages need to be installed. Refer to
  RHSA-2013:0277 for additional information.

  These updated libvirt packages include numerous bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Users
  are directed to the Red Hat Enterprise Linux 6.4 Technical Notes, linked
  to in the References, for information on the most significant of these
  changes.

  All users of libvirt are advised to upgrade to these updated packages,
  which fix these issues and add these enhancements. After installing the
  updated packages, libvirtd must be restarted ('service libvirtd restart')
  for this update to take effect.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-February/msg00040.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54353");
  script_oid("1.3.6.1.4.1.25623.1.0.870932");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-22 10:02:16 +0530 (Fri, 22 Feb 2013)");
  script_cve_id("CVE-2012-3411");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:0276-02");
  script_name("RedHat Update for libvirt RHSA-2013:0276-02");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-debuginfo", rpm:"libvirt-debuginfo~0.10.2~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~18.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
