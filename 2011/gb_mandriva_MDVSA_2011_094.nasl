# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-05/msg00018.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831397");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-23 16:55:31 +0200 (Mon, 23 May 2011)");
  script_xref(name:"MDVSA", value:"2011:094");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2011-0418");
  script_name("Mandriva Update for pure-ftpd MDVSA-2011:094 (pure-ftpd)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pure-ftpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1|2009\.0)");
  script_tag(name:"affected", value:"pure-ftpd on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"A denial-of-service (DoS) attack related to glob brace expansion was
  discovered and fixed in pure-ftpd (CVE-2011-0418).

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have been upgraded to the latest 1.0.32 version
  which is not vulnerable to this issue.");
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

  if ((res = isrpmvuln(pkg:"pure-ftpd", rpm:"pure-ftpd~1.0.32~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pure-ftpd-anon-upload", rpm:"pure-ftpd-anon-upload~1.0.32~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pure-ftpd-anonymous", rpm:"pure-ftpd-anonymous~1.0.32~0.1mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"pure-ftpd", rpm:"pure-ftpd~1.0.32~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pure-ftpd-anon-upload", rpm:"pure-ftpd-anon-upload~1.0.32~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pure-ftpd-anonymous", rpm:"pure-ftpd-anonymous~1.0.32~0.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2009.0")
{

  if ((res = isrpmvuln(pkg:"pure-ftpd", rpm:"pure-ftpd~1.0.32~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pure-ftpd-anon-upload", rpm:"pure-ftpd-anon-upload~1.0.32~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pure-ftpd-anonymous", rpm:"pure-ftpd-anonymous~1.0.32~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
