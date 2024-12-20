# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-11/msg00001.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831481");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-11-03 12:22:48 +0100 (Thu, 03 Nov 2011)");
  script_xref(name:"MDVSA", value:"2011:163");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-4074", "CVE-2011-4075");
  script_name("Mandriva Update for phpldapadmin MDVSA-2011:163 (phpldapadmin)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpldapadmin'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"phpldapadmin on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities was discovered and corrected in phpldapadmin:

  Input appended to the URL in cmd.php \(when cmd is set to _debug\)
  is not properly sanitised before being returned to the user. This can
  be exploited to execute arbitrary HTML and script code in a user's
  browser session in context of an affected site (CVE-2011-4074).

  Input passed to the orderby parameter in cmd.php \(when cmd is set
  to query_engine, query is set to none, and search is set to e.g. 1\)
  is not properly sanitised in lib/functions.php before being used in
  a create_function() function call. This can be exploited to inject
  and execute arbitrary PHP code (CVE-2011-4075).

  The updated packages have been upgraded to the latest version (1.2.2)
  which is not vulnerable to these issues.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"phpldapadmin", rpm:"phpldapadmin~1.2.2~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
