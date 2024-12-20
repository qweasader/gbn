# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-May/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870656");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-06 10:44:07 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2010-3851");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_xref(name:"RHSA", value:"2011:0586-01");
  script_name("RedHat Update for libguestfs RHSA-2011:0586-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libguestfs'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"libguestfs on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"libguestfs is a library for accessing and modifying guest disk images.

  libguestfs relied on the format auto-detection in QEMU rather than
  allowing the guest image file format to be specified. A privileged guest
  user could potentially use this flaw to read arbitrary files on the host
  that were accessible to a user on that host who was running a program that
  utilized the libguestfs library. (CVE-2010-3851)

  This erratum upgrades libguestfs to upstream version 1.7.17, which includes
  a number of bug fixes and one enhancement. Documentation for these bug
  fixes and this enhancement is provided in the Technical Notes document,
  linked to in the References section.

  All libguestfs users are advised to upgrade to these updated packages,
  which correct this issue, and fix the bugs and add the enhancement noted
  in the Technical Notes.");
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

  if ((res = isrpmvuln(pkg:"guestfish", rpm:"guestfish~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs", rpm:"libguestfs~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-debuginfo", rpm:"libguestfs-debuginfo~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-java", rpm:"libguestfs-java~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-mount", rpm:"libguestfs-mount~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools", rpm:"libguestfs-tools~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libguestfs-tools-c", rpm:"libguestfs-tools-c~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Sys-Guestfs", rpm:"perl-Sys-Guestfs~1.7.17~17.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
