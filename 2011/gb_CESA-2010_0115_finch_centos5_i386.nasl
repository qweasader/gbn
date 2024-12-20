# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.880665");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2010:0115");
  script_cve_id("CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423");
  script_name("CentOS Update for finch CESA-2010:0115 centos5 i386");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-February/016524.html");
  script_xref(name:"URL", value:"http://developer.pidgin.im/wiki/ChangeLog");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'finch'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"finch on CentOS 5");
  script_tag(name:"insight", value:"Pidgin is an instant messaging program which can log in to multiple
  accounts on multiple instant messaging networks simultaneously.

  An input sanitization flaw was found in the way Pidgin's MSN protocol
  implementation handled MSNSLP invitations. A remote attacker could send a
  specially-crafted INVITE request that would cause a denial of service
  (memory corruption and Pidgin crash). (CVE-2010-0277)

  A denial of service flaw was found in Finch's XMPP chat implementation,
  when using multi-user chat. If a Finch user in a multi-user chat session
  were to change their nickname to contain the HTML 'br' element, it would
  cause Finch to crash. (CVE-2010-0420)

  Red Hat would like to thank Sadrul Habib Chowdhury of the Pidgin project
  for responsibly reporting the CVE-2010-0420 issue.

  A denial of service flaw was found in the way Pidgin processed emoticon
  images. A remote attacker could flood the victim with emoticon images
  during mutual communication, leading to excessive CPU use. (CVE-2010-0423)

  These packages upgrade Pidgin to version 2.6.6. Refer to the linked Pidgin release
  notes for a full list of changes.

  All Pidgin users are advised to upgrade to these updated packages, which
  correct these issues. Pidgin must be restarted for this update to take
  effect.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.6.6~1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
