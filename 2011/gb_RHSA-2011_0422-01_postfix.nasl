# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-April/msg00003.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870418");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-04-11 15:05:25 +0200 (Mon, 11 Apr 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"RHSA", value:"2011:0422-01");
  script_cve_id("CVE-2008-2937", "CVE-2011-0411");
  script_name("RedHat Update for postfix RHSA-2011:0422-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(5|4)");
  script_tag(name:"affected", value:"postfix on Red Hat Enterprise Linux (v. 5 server),
  Red Hat Enterprise Linux AS version 4,
  Red Hat Enterprise Linux ES version 4,
  Red Hat Enterprise Linux WS version 4");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
  and TLS.

  It was discovered that Postfix did not flush the received SMTP commands
  buffer after switching to TLS encryption for an SMTP session. A
  man-in-the-middle attacker could use this flaw to inject SMTP commands into
  a victim's session during the plain text phase. This would lead to those
  commands being processed by Postfix after TLS encryption is enabled,
  possibly allowing the attacker to steal the victim's mail or authentication
  credentials. (CVE-2011-0411)

  It was discovered that Postfix did not properly check the permissions of
  users' mailbox files. A local attacker able to create files in the mail
  spool directory could use this flaw to create mailbox files for other local
  users, and be able to read mail delivered to those users. (CVE-2008-2937)

  Red Hat would like to thank the CERT/CC for reporting CVE-2011-0411, and
  Sebastian Krahmer of the SuSE Security Team for reporting CVE-2008-2937.
  The CERT/CC acknowledges Wietse Venema as the original reporter of
  CVE-2011-0411.

  Users of Postfix are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues. After installing this
  update, the postfix service will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.3.3~2.2.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~2.3.3~2.2.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-pflogsumm", rpm:"postfix-pflogsumm~2.3.3~2.2.el5_6", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_4")
{

  if ((res = isrpmvuln(pkg:"postfix", rpm:"postfix~2.2.10~1.4.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-debuginfo", rpm:"postfix-debuginfo~2.2.10~1.4.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"postfix-pflogsumm", rpm:"postfix-pflogsumm~2.2.10~1.4.el4", rls:"RHENT_4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
