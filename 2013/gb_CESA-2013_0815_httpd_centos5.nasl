# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"affected", value:"httpd on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular web server.

  Cross-site scripting (XSS) flaws were found in the mod_proxy_balancer
  module's manager web interface. If a remote attacker could trick a user,
  who was logged into the manager web interface, into visiting a
  specially-crafted URL, it would lead to arbitrary web script execution in
  the context of the user's manager interface session. (CVE-2012-4558)

  It was found that mod_rewrite did not filter terminal escape sequences from
  its log file. If mod_rewrite was configured with the RewriteLog directive,
  a remote attacker could use specially-crafted HTTP requests to inject
  terminal escape sequences into the mod_rewrite log file. If a victim viewed
  the log file with a terminal emulator, it could result in arbitrary command
  execution with the privileges of that user. (CVE-2013-1862)

  Cross-site scripting (XSS) flaws were found in the mod_info, mod_status,
  mod_imagemap, mod_ldap, and mod_proxy_ftp modules. An attacker could
  possibly use these flaws to perform XSS attacks if they were able to make
  the victim's browser generate an HTTP request with a specially-crafted Host
  header. (CVE-2012-3499)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon will be restarted automatically.");
  script_oid("1.3.6.1.4.1.25623.1.0.881733");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-05-17 09:53:40 +0530 (Fri, 17 May 2013)");
  script_cve_id("CVE-2012-3499", "CVE-2012-4558", "CVE-2013-1862");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("CentOS Update for httpd CESA-2013:0815 centos5");

  script_xref(name:"CESA", value:"2013:0815");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-May/019720.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~78.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~78.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~78.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~78.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
