# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871195");
  script_version("2024-03-21T05:06:54+0000");
  script_tag(name:"last_modification", value:"2024-03-21 05:06:54 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2014-07-01 23:23:58 +0530 (Tue, 01 Jul 2014)");
  script_cve_id("CVE-2014-3430");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for dovecot RHSA-2014:0790-01");


  script_tag(name:"affected", value:"dovecot on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Dovecot is an IMAP server, written with security primarily in mind, for
Linux and other UNIX-like systems. It also contains a small POP3 server.
It supports mail in both the maildir or mbox format. The SQL drivers and
authentication plug-ins are provided as subpackages.

It was discovered that Dovecot did not properly discard connections trapped
in the SSL/TLS handshake phase. A remote attacker could use this flaw to
cause a denial of service on an IMAP/POP3 server by exhausting the pool of
available connections and preventing further, legitimate connections to the
IMAP/POP3 server to be made. (CVE-2014-3430)

All dovecot users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the dovecot service will be restarted automatically.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"RHSA", value:"2014:0790-01");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-June/msg00053.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.2.10~4.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-debuginfo", rpm:"dovecot-debuginfo~2.2.10~4.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-mysql", rpm:"dovecot-mysql~2.2.10~4.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-pgsql", rpm:"dovecot-pgsql~2.2.10~4.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.2.10~4.el7_0.1", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.0.9~7.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-debuginfo", rpm:"dovecot-debuginfo~2.0.9~7.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-mysql", rpm:"dovecot-mysql~2.0.9~7.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-pgsql", rpm:"dovecot-pgsql~2.0.9~7.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.0.9~7.el6_5.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
