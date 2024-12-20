# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015891.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880708");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1060");
  script_cve_id("CVE-2009-1373", "CVE-2009-1374", "CVE-2009-1375", "CVE-2009-1376", "CVE-2008-2927");
  script_name("CentOS Update for finch CESA-2009:1060 centos5 i386");

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

  A buffer overflow flaw was found in the way Pidgin initiates file transfers
  when using the Extensible Messaging and Presence Protocol (XMPP). If a
  Pidgin client initiates a file transfer, and the remote target sends a
  malformed response, it could cause Pidgin to crash or, potentially, execute
  arbitrary code with the permissions of the user running Pidgin. This flaw
  only affects accounts using XMPP, such as Jabber and Google Talk.
  (CVE-2009-1373)

  A denial of service flaw was found in Pidgin's QQ protocol decryption
  handler. When the QQ protocol decrypts packet information, heap data can be
  overwritten, possibly causing Pidgin to crash. (CVE-2009-1374)

  A flaw was found in the way Pidgin's PurpleCircBuffer object is expanded.
  If the buffer is full when more data arrives, the data stored in this
  buffer becomes corrupted. This corrupted data could result in confusing or
  misleading data being presented to the user, or possibly crash Pidgin.
  (CVE-2009-1375)

  It was discovered that on 32-bit platforms, the Red Hat Security Advisory
  RHSA-2008:0584 provided an incomplete fix for the integer overflow flaw
  affecting Pidgin's MSN protocol handler. If a Pidgin client receives a
  specially-crafted MSN message, it may be possible to execute arbitrary code
  with the permissions of the user running Pidgin. (CVE-2009-1376)

  Note: By default, when using an MSN account, only users on your buddy list
  can send you messages. This prevents arbitrary MSN users from exploiting
  this flaw.

  All Pidgin users should upgrade to these updated packages, which contain
  backported patches to resolve these issues. Pidgin must be restarted for
  this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.5.5~3.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
