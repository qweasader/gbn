# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00030.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870778");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:57 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2012-2102");
  script_xref(name:"RHSA", value:"2012:0874-04");
  script_name("RedHat Update for mysql RHSA-2012:0874-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"mysql on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"MySQL is a multi-user, multi-threaded SQL database server. It consists of
  the MySQL server daemon (mysqld) and many client programs and libraries.

  A flaw was found in the way MySQL processed HANDLER READ NEXT statements
  after deleting a record. A remote, authenticated attacker could use this
  flaw to provide such requests, causing mysqld to crash. This issue only
  caused a temporary denial of service, as mysqld was automatically restarted
  after the crash. (CVE-2012-2102)

  This update also adds the following enhancement:

  * The InnoDB storage engine is built-in for all architectures. This update
  adds InnoDB Plugin, the InnoDB storage engine as a plug-in for the 32-bit
  x86, AMD64, and Intel 64 architectures. The plug-in offers additional
  features and better performance than when using the built-in InnoDB storage
  engine. Refer to the MySQL documentation, linked to in the References
  section, for information about enabling the plug-in. (BZ#740224)

  All MySQL users should upgrade to these updated packages, which add this
  enhancement and contain a backported patch to correct this issue. After
  installing this update, the MySQL server daemon (mysqld) will be restarted
  automatically.");
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

  if ((res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.1.61~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-bench", rpm:"mysql-bench~5.1.61~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-debuginfo", rpm:"mysql-debuginfo~5.1.61~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-devel", rpm:"mysql-devel~5.1.61~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-libs", rpm:"mysql-libs~5.1.61~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-server", rpm:"mysql-server~5.1.61~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mysql-test", rpm:"mysql-test~5.1.61~4.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
