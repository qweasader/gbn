# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881871");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-11 10:29:40 +0530 (Tue, 11 Feb 2014)");
  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for finch CESA-2014:0139 centos5");

  script_tag(name:"affected", value:"finch on CentOS 5");
  script_tag(name:"insight", value:"Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A heap-based buffer overflow flaw was found in the way Pidgin processed
certain HTTP responses. A malicious server could send a specially crafted
HTTP response, causing Pidgin to crash or potentially execute arbitrary
code with the permissions of the user running Pidgin. (CVE-2013-6485)

Multiple heap-based buffer overflow flaws were found in several protocol
plug-ins in Pidgin (Gadu-Gadu, MXit, SIMPLE). A malicious server could send
a specially crafted message, causing Pidgin to crash or potentially execute
arbitrary code with the permissions of the user running Pidgin.
(CVE-2013-6487, CVE-2013-6489, CVE-2013-6490)

Multiple denial of service flaws were found in several protocol plug-ins in
Pidgin (Yahoo!, XMPP, MSN, stun, IRC). A remote attacker could use these
flaws to crash Pidgin by sending a specially crafted message.
(CVE-2012-6152, CVE-2013-6477, CVE-2013-6481, CVE-2013-6482, CVE-2013-6484,
CVE-2014-0020)

It was found that the Pidgin XMPP protocol plug-in did not verify the
origin of 'iq' replies. A remote attacker could use this flaw to spoof an
'iq' reply, which could lead to injection of fake data or cause Pidgin to
crash via a NULL pointer dereference. (CVE-2013-6483)

A flaw was found in the way Pidgin parsed certain HTTP response headers.
A remote attacker could use this flaw to crash Pidgin via a specially
crafted HTTP response header. (CVE-2013-6479)

It was found that Pidgin crashed when a mouse pointer was hovered over a
long URL. A remote attacker could use this flaw to crash Pidgin by sending
a message containing a long URL string. (CVE-2013-6478)

Red Hat would like to thank the Pidgin project for reporting these issues.
Upstream acknowledges Thijs Alkemade, Robert Vehse, Jaime Breva Ribes,
Jacob Appelbaum of the Tor Project, Daniel Atallah, Fabian Yamaguchi and
Christian Wressnegger of the University of Goettingen, Matt Jones of
Volvent, and Yves Younan, Ryan Pentney, and Pawel Janic of Sourcefire VRT
as the original reporters of these issues.

All pidgin users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. Pidgin must be
restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0139");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-February/020141.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'finch'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.6~32.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}