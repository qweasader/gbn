# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-January/015564.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880718");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_xref(name:"CESA", value:"2009:0057");
  script_cve_id("CVE-2009-0030");
  script_name("CentOS Update for squirrelmail CESA-2009:0057 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squirrelmail'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"squirrelmail on CentOS 5");
  script_tag(name:"insight", value:"SquirrelMail is an easy-to-configure, standards-based, webmail package
  written in PHP. It includes built-in PHP support for the IMAP and SMTP
  protocols, and pure HTML 4.0 page-rendering (with no JavaScript required)
  for maximum browser-compatibility, strong MIME support, address books, and
  folder manipulation.

  The Red Hat SquirrelMail packages provided by the RHSA-2009:0010 advisory
  introduced a session handling flaw. Users who logged back into SquirrelMail
  without restarting their web browsers were assigned fixed session
  identifiers. A remote attacker could make use of that flaw to hijack user
  sessions. (CVE-2009-0030)

  SquirrelMail users should upgrade to this updated package, which contains a
  patch to correct this issue. As well, all users who used affected versions
  of SquirrelMail should review their preferences.");
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

  if ((res = isrpmvuln(pkg:"squirrelmail", rpm:"squirrelmail~1.4.8~5.el5.centos.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
