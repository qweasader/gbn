# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-September/msg00025.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870837");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-09-22 11:57:26 +0530 (Sat, 22 Sep 2012)");
  script_cve_id("CVE-2012-4425");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"RHSA", value:"2012:1284-01");
  script_name("RedHat Update for spice-gtk RHSA-2012:1284-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spice-gtk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"spice-gtk on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The spice-gtk packages provide a GIMP Toolkit (GTK+) widget for SPICE
  (Simple Protocol for Independent Computing Environments) clients. Both
  Virtual Machine Manager and Virtual Machine Viewer can make use of this
  widget to access virtual machines using the SPICE protocol.

  It was discovered that the spice-gtk setuid helper application,
  spice-client-glib-usb-acl-helper, did not clear the environment variables
  read by the libraries it uses. A local attacker could possibly use this
  flaw to escalate their privileges by setting specific environment variables
  before running the helper application. (CVE-2012-4425)

  Red Hat would like to thank Sebastian Krahmer of the SUSE Security Team for
  reporting this issue.

  All users of spice-gtk are advised to upgrade to these updated packages,
  which contain a backported patch to correct this issue.");
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

  if ((res = isrpmvuln(pkg:"spice-glib", rpm:"spice-glib~0.11~11.el6_3.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk", rpm:"spice-gtk~0.11~11.el6_3.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-debuginfo", rpm:"spice-gtk-debuginfo~0.11~11.el6_3.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"spice-gtk-python", rpm:"spice-gtk-python~0.11~11.el6_3.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
