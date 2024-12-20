# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882435");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-24 06:15:05 +0100 (Thu, 24 Mar 2016)");
  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 15:18:00 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for emacs-git CESA-2016:0496 centos6");
  script_tag(name:"summary", value:"Check the version of emacs-git");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Git is a distributed revision control system
with a decentralized architecture. As opposed to centralized version control
systems with a client-server model, Git ensures that each working copy of a Git
repository is an exact copy with complete revision history. This not only allows the
user to work on and contribute to projects without the need to have permission to
push the changes to their official repositories, but also makes it possible for
the user to work with no network connection.

An integer truncation flaw and an integer overflow flaw, both leading to a
heap-based buffer overflow, were found in the way Git processed certain
path information. A remote attacker could create a specially crafted Git
repository that would cause a Git client or server to crash or, possibly,
execute arbitrary code. (CVE-2016-2315, CVE-2016-2324)

All git users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"emacs-git on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:0496");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-March/021770.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"emacs-git", rpm:"emacs-git~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"emacs-git-el", rpm:"emacs-git-el~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"git", rpm:"git~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"git-all", rpm:"git-all~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"git-cvs", rpm:"git-cvs~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"git-daemon", rpm:"git-daemon~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"git-email", rpm:"git-email~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"git-gui", rpm:"git-gui~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gitk", rpm:"gitk~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"git-svn", rpm:"git-svn~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gitweb", rpm:"gitweb~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-Git", rpm:"perl-Git~1.7.1~4.el6_7.1", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
