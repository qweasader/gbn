# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871083");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2013-11-21 10:44:20 +0530 (Thu, 21 Nov 2013)");
  script_cve_id("CVE-2013-4419");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for libguestfs RHSA-2013:1536-02");


  script_tag(name:"affected", value:"libguestfs on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Libguestfs is a library and set of tools for accessing and modifying guest
disk images.

It was found that guestfish, which enables shell scripting and command line
access to libguestfs, insecurely created the temporary directory used to
store the network socket when started in server mode. A local attacker
could use this flaw to intercept and modify other user's guestfish command,
allowing them to perform arbitrary guestfish actions with the privileges of
a different user, or use this flaw to obtain authentication credentials.
(CVE-2013-4419)

This issue was discovered by Michael Scherer of the Red Hat Regional IT
team.

These updated libguestfs packages include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5 Technical
Notes, linked to in the References, for information on the most significant
of these changes.

All libguestfs users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2013:1536-02");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-November/msg00016.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libguestfs'
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

  if ((res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.20.11~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-debuginfo", rpm:"libguestfs-debuginfo~1.20.11~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-java", rpm:"libguestfs-java~1.20.11~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.20.11~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.20.11~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.20.11~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libguestfs", rpm:"python-libguestfs~1.20.11~2.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
