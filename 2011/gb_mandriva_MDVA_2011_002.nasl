# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-01/msg00015.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831313");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-21 14:59:01 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"MDVA", value:"2011:002");
  script_name("Mandriva Update for cyrus-sasl MDVA-2011:002 (cyrus-sasl)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-sasl'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.0|2009\.0)");
  script_tag(name:"affected", value:"cyrus-sasl on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"The saslauth daemon (cyrus-sasl) could crash under heavy load.

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages has been patched to address this problem.");
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

  if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~29.2mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.23~1.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2", rpm:"libsasl2~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-devel", rpm:"libsasl2-devel~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-anonymous", rpm:"libsasl2-plug-anonymous~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-crammd5", rpm:"libsasl2-plug-crammd5~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-digestmd5", rpm:"libsasl2-plug-digestmd5~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-gssapi", rpm:"libsasl2-plug-gssapi~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-ldapdb", rpm:"libsasl2-plug-ldapdb~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-login", rpm:"libsasl2-plug-login~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-ntlm", rpm:"libsasl2-plug-ntlm~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-otp", rpm:"libsasl2-plug-otp~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-plain", rpm:"libsasl2-plug-plain~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-sasldb", rpm:"libsasl2-plug-sasldb~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsasl2-plug-sql", rpm:"libsasl2-plug-sql~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2", rpm:"lib64sasl2~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-devel", rpm:"lib64sasl2-devel~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-anonymous", rpm:"lib64sasl2-plug-anonymous~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-crammd5", rpm:"lib64sasl2-plug-crammd5~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-digestmd5", rpm:"lib64sasl2-plug-digestmd5~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-gssapi", rpm:"lib64sasl2-plug-gssapi~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ldapdb", rpm:"lib64sasl2-plug-ldapdb~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-login", rpm:"lib64sasl2-plug-login~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-ntlm", rpm:"lib64sasl2-plug-ntlm~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-otp", rpm:"lib64sasl2-plug-otp~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-plain", rpm:"lib64sasl2-plug-plain~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sasldb", rpm:"lib64sasl2-plug-sasldb~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64sasl2-plug-sql", rpm:"lib64sasl2-plug-sql~2.1.22~29.2mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
