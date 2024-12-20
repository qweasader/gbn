# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881420");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-07-30 17:50:09 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-4341");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"CESA", value:"2011:0975");
  script_name("CentOS Update for sssd CESA-2011:0975 centos5 x86_64");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017983.html");
  script_xref(name:"URL", value:"https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/5/html/5.7_Technical_Notes/sssd.html#RHSA-2011-0975");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sssd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"sssd on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The System Security Services Daemon (SSSD) provides a set of daemons to
  manage access to remote directories and authentication mechanisms. It
  provides an NSS and PAM interface toward the system and a pluggable
  back-end system to connect to multiple different account sources. It is
  also the basis to provide client auditing and policy services for projects
  such as FreeIPA.

  A flaw was found in the SSSD PAM responder that could allow a local
  attacker to force SSSD to enter an infinite loop via a carefully-crafted
  packet. With SSSD unresponsive, legitimate users could be denied the
  ability to log in to the system. (CVE-2010-4341)

  Red Hat would like to thank Sebastian Krahmer for reporting this issue.

  These updated sssd packages include a number of bug fixes and enhancements.
  Space precludes documenting all of these changes in this advisory. Refer to
  the linked Red Hat Enterprise Linux 5.7 Technical Notes for information about
  these changes.

  All sssd users are advised to upgrade to these updated sssd packages, which
  upgrade SSSD to upstream version 1.5.1 to correct this issue, and fix the
  bugs and add the enhancements noted in the Technical Notes.");
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

  if ((res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.5.1~37.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.5.1~37.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.5.1~37.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
