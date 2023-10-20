# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-12/msg00014.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831509");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-12-19 12:25:10 +0530 (Mon, 19 Dec 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2011:189");
  script_cve_id("CVE-2011-4516", "CVE-2011-4517");
  script_name("Mandriva Update for jasper MDVSA-2011:189 (jasper)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jasper'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(mes5|2010\.1)");
  script_tag(name:"affected", value:"jasper on Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been discovered and corrected in jasper:
  Heap-based buffer overflow in the jpc_cox_getcompparms function in
  libjasper/jpc/jpc_cs.c in JasPer 1.900.1 allows remote attackers to
  execute arbitrary code or cause a denial of service (memory corruption)
  via a crafted numrlvls value in a JPEG2000 file (CVE-2011-4516).

  The jpc_crg_getparms function in libjasper/jpc/jpc_cs.c in JasPer
  1.900.1 uses an incorrect data type during a certain size calculation,
  which allows remote attackers to trigger a heap-based buffer overflow
  and execute arbitrary code, or cause a denial of service (heap memory
  corruption), via a malformed JPEG2000 file (CVE-2011-4517).

  The updated packages have been patched to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~4.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.1~4.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjasper1-devel", rpm:"libjasper1-devel~1.900.1~4.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjasper1-static-devel", rpm:"libjasper1-static-devel~1.900.1~4.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64jasper1", rpm:"lib64jasper1~1.900.1~4.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64jasper1-devel", rpm:"lib64jasper1-devel~1.900.1~4.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64jasper1-static-devel", rpm:"lib64jasper1-static-devel~1.900.1~4.3mdvmes5.2", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"jasper", rpm:"jasper~1.900.1~12.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjasper1", rpm:"libjasper1~1.900.1~12.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjasper-devel", rpm:"libjasper-devel~1.900.1~12.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjasper-static-devel", rpm:"libjasper-static-devel~1.900.1~12.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64jasper1", rpm:"lib64jasper1~1.900.1~12.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64jasper-devel", rpm:"lib64jasper-devel~1.900.1~12.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lib64jasper-static-devel", rpm:"lib64jasper-static-devel~1.900.1~12.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
