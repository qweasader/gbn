# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-10/msg00017.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831460");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-10-10 16:05:48 +0200 (Mon, 10 Oct 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_xref(name:"MDVSA", value:"2011:144");
  script_cve_id("CVE-2011-3368");
  script_name("Mandriva Update for apache MDVSA-2011:144 (apache)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1|2009\.0)");
  script_tag(name:"affected", value:"apache on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"A vulnerability has been discovered and corrected in apache:

  The mod_proxy module in the Apache HTTP Server 1.3.x through 1.3.42,
  2.0.x through 2.0.64, and 2.2.x through 2.2.21 does not properly
  interact with use of (1) RewriteRule and (2) ProxyPassMatch pattern
  matches for configuration of a reverse proxy, which allows remote
  attackers to send requests to intranet servers via a malformed URI
  containing an initial \@ (at sign) character (CVE-2011-3368).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have been patched to correct this issue.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://store.mandriva.com/product_info.php?cPath=149&amp;amp;products_id=490");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-peruser", rpm:"apache-mpm-peruser~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache", rpm:"apache~2.2.9~12.13mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_proxy_scgi", rpm:"apache-mod_proxy_scgi~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_reqtimeout", rpm:"apache-mod_reqtimeout~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-peruser", rpm:"apache-mpm-peruser~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache", rpm:"apache~2.2.15~3.4mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"apache-base", rpm:"apache-base~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-devel", rpm:"apache-devel~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-htcacheclean", rpm:"apache-htcacheclean~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_authn_dbd", rpm:"apache-mod_authn_dbd~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_cache", rpm:"apache-mod_cache~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_dav", rpm:"apache-mod_dav~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_dbd", rpm:"apache-mod_dbd~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_deflate", rpm:"apache-mod_deflate~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_disk_cache", rpm:"apache-mod_disk_cache~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_file_cache", rpm:"apache-mod_file_cache~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_ldap", rpm:"apache-mod_ldap~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_mem_cache", rpm:"apache-mod_mem_cache~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_proxy", rpm:"apache-mod_proxy~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_proxy_ajp", rpm:"apache-mod_proxy_ajp~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_ssl", rpm:"apache-mod_ssl~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-modules", rpm:"apache-modules~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mod_userdir", rpm:"apache-mod_userdir~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-event", rpm:"apache-mpm-event~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-itk", rpm:"apache-mpm-itk~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-peruser", rpm:"apache-mpm-peruser~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-prefork", rpm:"apache-mpm-prefork~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-mpm-worker", rpm:"apache-mpm-worker~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache-source", rpm:"apache-source~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"apache", rpm:"apache~2.2.9~12.13mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
