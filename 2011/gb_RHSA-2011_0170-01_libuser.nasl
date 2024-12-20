# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00019.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870381");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:59:01 +0100 (Fri, 21 Jan 2011)");
  script_xref(name:"RHSA", value:"2011:0170-01");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2011-0002");
  script_name("RedHat Update for libuser RHSA-2011:0170-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libuser'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(5|4)");
  script_tag(name:"affected", value:"libuser on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The libuser library implements a standardized interface for manipulating
  and administering user and group accounts. Sample applications that are
  modeled after applications from the shadow password suite (shadow-utils)
  are included in these packages.

  It was discovered that libuser did not set the password entry correctly
  when creating LDAP (Lightweight Directory Access Protocol) users. If an
  administrator did not assign a password to an LDAP based user account,
  either at account creation with luseradd, or with lpasswd after account
  creation, an attacker could use this flaw to log into that account with a
  default password string that should have been rejected. (CVE-2011-0002)

  Note: LDAP administrators that have used libuser tools to add users should
  check existing user accounts for plain text passwords, and reset them as
  necessary.

  Users of libuser should upgrade to these updated packages, which contain a
  backported patch to correct this issue.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"libuser", rpm:"libuser~0.54.7~2.1.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-debuginfo", rpm:"libuser-debuginfo~0.54.7~2.1.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-devel", rpm:"libuser-devel~0.54.7~2.1.el5_5.2", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"libuser", rpm:"libuser~0.52.5~1.1.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-debuginfo", rpm:"libuser-debuginfo~0.52.5~1.1.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libuser-devel", rpm:"libuser-devel~0.52.5~1.1.el4_8.1", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
