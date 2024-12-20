# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-June/msg00011.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870660");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-06-06 10:44:29 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-1775");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_xref(name:"RHSA", value:"2011:0871-01");
  script_name("RedHat Update for tigervnc RHSA-2011:0871-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tigervnc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"tigervnc on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Virtual Network Computing (VNC) is a remote display system which allows you
  to view a computer's desktop environment not only on the machine where it
  is running, but from anywhere on the Internet and from a wide variety of
  machine architectures. TigerVNC is a suite of VNC servers and clients.

  It was discovered that vncviewer could prompt for and send authentication
  credentials to a remote server without first properly validating the
  server's X.509 certificate. As vncviewer did not indicate that the
  certificate was bad or missing, a man-in-the-middle attacker could use this
  flaw to trick a vncviewer client into connecting to a spoofed VNC server,
  allowing the attacker to obtain the client's credentials. (CVE-2011-1775)

  All tigervnc users should upgrade to these updated packages, which contain
  a backported patch to correct this issue.");
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

  if ((res = isrpmvuln(pkg:"tigervnc", rpm:"tigervnc~1.0.90~0.15.20110314svn4359.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tigervnc-debuginfo", rpm:"tigervnc-debuginfo~1.0.90~0.15.20110314svn4359.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tigervnc-server", rpm:"tigervnc-server~1.0.90~0.15.20110314svn4359.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
