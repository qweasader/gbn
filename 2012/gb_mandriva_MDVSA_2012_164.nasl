# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://www.mandriva.com/en/support/security/advisories/?name=MDVSA-2012:164");
  script_oid("1.3.6.1.4.1.25623.1.0.831746");
  script_version("2023-07-14T05:06:08+0000");
  script_tag(name:"last_modification", value:"2023-07-14 05:06:08 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-12 09:21:18 +0530 (Fri, 12 Oct 2012)");
  script_cve_id("CVE-2011-1202", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2012:164");
  script_name("Mandriva Update for libxslt MDVSA-2012:164 (libxslt)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxslt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2011\.0|mes5\.2)");
  script_tag(name:"affected", value:"libxslt on Mandriva Linux 2011.0,
  Mandriva Enterprise Server 5.2");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in libxslt:

  Unspecified vulnerability in XSLT allows remote attackers to obtain
  potentially sensitive information about heap memory addresses via
  unknown vectors (CVE-2011-1202).

  libxslt 1.1.26 and earlier does not properly manage memory, which might
  allow remote attackers to cause a denial of service (application crash)
  via a crafted XSLT expression that is not properly identified during
  XPath navigation, related to (1) the xsltCompileLocationPathPattern
  function in libxslt/pattern.c and (2) the xsltGenerateIdFunction
  function in libxslt/functions.c (CVE-2012-2870).

  libxml2 2.9.0-rc1 and earlier does not properly support a cast of
  an unspecified variable during handling of XSL transforms, which
  allows remote attackers to cause a denial of service or possibly have
  unknown other impact via a crafted document, related to the _xmlNs
  data structure in include/libxml/tree.h (CVE-2012-2871).

  Double free vulnerability in libxslt allows remote attackers to cause
  a denial of service or possibly have unspecified other impact via
  vectors related to XSL transforms (CVE-2012-2893).

  The updated packages have been patched to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_2011.0")
{

  if ((res = isrpmvuln(pkg:"libxslt1", rpm:"libxslt1~1.1.26~4.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.26~4.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxslt", rpm:"python-libxslt~1.1.26~4.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xsltproc", rpm:"xsltproc~1.1.26~4.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xslt1", rpm:"lib64xslt1~1.1.26~4.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xslt-devel", rpm:"lib64xslt-devel~1.1.26~4.3", rls:"MNDK_2011.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_mes5.2")
{

  if ((res = isrpmvuln(pkg:"libxslt1", rpm:"libxslt1~1.1.24~3.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-devel", rpm:"libxslt-devel~1.1.24~3.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxslt-proc", rpm:"libxslt-proc~1.1.24~3.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-libxslt", rpm:"python-libxslt~1.1.24~3.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xslt1", rpm:"lib64xslt1~1.1.24~3.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64xslt-devel", rpm:"lib64xslt-devel~1.1.24~3.3mdvmes5.2", rls:"MNDK_mes5.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
