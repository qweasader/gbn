# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-February/019225.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881587");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-02-04 09:55:13 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2012-5659", "CVE-2012-5660");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2013:0215");
  script_name("CentOS Update for libreport CESA-2013:0215 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreport'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"libreport on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
  defects in applications and to create a bug report with all the information
  needed by a maintainer to fix it. It uses a plug-in system to extend its
  functionality. libreport provides an API for reporting different problems
  in applications to different bug targets, such as Bugzilla, FTP, and Trac.

  It was found that the
  /usr/libexec/abrt-action-install-debuginfo-to-abrt-cache tool did not
  sufficiently sanitize its environment variables. This could lead to Python
  modules being loaded and run from non-standard directories (such as /tmp/).
  A local attacker could use this flaw to escalate their privileges to that
  of the abrt user. (CVE-2012-5659)

  A race condition was found in the way ABRT handled the directories used to
  store information about crashes. A local attacker with the privileges of
  the abrt user could use this flaw to perform a symbolic link attack,
  possibly allowing them to escalate their privileges to root.
  (CVE-2012-5660)

  Red Hat would like to thank Martin Carpenter of Citco for reporting the
  CVE-2012-5660 issue. CVE-2012-5659 was discovered by Miloslav Trma of Red
  Hat.

  All users of abrt and libreport are advised to upgrade to these updated
  packages, which correct these issues.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-devel", rpm:"libreport-devel~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-gtk-devel", rpm:"libreport-gtk-devel~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-bugzilla", rpm:"libreport-plugin-bugzilla~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-plugin-rhtsupport", rpm:"libreport-plugin-rhtsupport~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.0.9~5.el6.centos.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
