# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881972");
  script_version("2023-07-11T05:06:07+0000");
  script_tag(name:"last_modification", value:"2023-07-11 05:06:07 +0000 (Tue, 11 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-07-28 16:34:43 +0530 (Mon, 28 Jul 2014)");
  script_cve_id("CVE-2014-0118", "CVE-2014-0226", "CVE-2014-0231");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for httpd CESA-2014:0920 centos5");

  script_tag(name:"affected", value:"httpd on CentOS 5");
  script_tag(name:"insight", value:"The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

A race condition flaw, leading to heap-based buffer overflows, was found in
the mod_status httpd module. A remote attacker able to access a status page
served by mod_status on a server using a threaded Multi-Processing Module
(MPM) could send a specially crafted request that would cause the httpd
child process to crash or, possibly, allow the attacker to execute
arbitrary code with the privileges of the 'apache' user. (CVE-2014-0226)

A denial of service flaw was found in the way httpd's mod_deflate module
handled request body decompression (configured via the 'DEFLATE' input
filter). A remote attacker able to send a request whose body would be
decompressed could use this flaw to consume an excessive amount of system
memory and CPU on the target system. (CVE-2014-0118)

A denial of service flaw was found in the way httpd's mod_cgid module
executed CGI scripts that did not read data from the standard input.
A remote attacker could submit a specially crafted request that would cause
the httpd child process to hang indefinitely. (CVE-2014-0231)

All httpd users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, the httpd daemon will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:0920");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-July/020440.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
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

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~87.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~87.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~87.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~87.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
