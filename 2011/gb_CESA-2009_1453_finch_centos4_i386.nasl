# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.880899");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2009:1453");
  script_cve_id("CVE-2009-2703", "CVE-2009-3026", "CVE-2009-3083", "CVE-2009-3085");
  script_name("CentOS Update for finch CESA-2009:1453 centos4 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016169.html");
  script_xref(name:"URL", value:"http://developer.pidgin.im/wiki/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'finch'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"finch on CentOS 4");
  script_tag(name:"insight", value:"Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously. Info/Query
  (IQ) is an Extensible Messaging and Presence Protocol (XMPP) specific
  request-response mechanism.

  A NULL pointer dereference flaw was found in the way the Pidgin XMPP
  protocol plug-in processes IQ error responses when trying to fetch a custom
  smiley. A remote client could send a specially-crafted IQ error response
  that would crash Pidgin. (CVE-2009-3085)

  A NULL pointer dereference flaw was found in the way the Pidgin IRC
  protocol plug-in handles IRC topics. A malicious IRC server could send a
  specially-crafted IRC TOPIC message, which once received by Pidgin, would
  lead to a denial of service (Pidgin crash). (CVE-2009-2703)

  It was discovered that, when connecting to certain, very old Jabber servers
  via XMPP, Pidgin may ignore the 'Require SSL/TLS' setting. In these
  situations, a non-encrypted connection is established rather than the
  connection failing, causing the user to believe they are using an encrypted
  connection when they are not, leading to sensitive information disclosure
  (session sniffing). (CVE-2009-3026)

  A NULL pointer dereference flaw was found in the way the Pidgin MSN
  protocol plug-in handles improper MSNSLP invitations. A remote attacker
  could send a specially-crafted MSNSLP invitation request, which once
  accepted by a valid Pidgin user, would lead to a denial of service (Pidgin
  crash). (CVE-2009-3083)

  These packages upgrade Pidgin to version 2.6.2. Refer to the linked Pidgin release
  notes for a full list of changes.

  All Pidgin users should upgrade to these updated packages, which correct
  these issues. Pidgin must be restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.2~2.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
