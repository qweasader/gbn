# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882962");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-10-16 06:20:18 +0200 (Tue, 16 Oct 2018)");
  script_cve_id("CVE-2018-10194", "CVE-2018-15910", "CVE-2018-16509", "CVE-2018-16542");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ghostscript CESA-2018:2918 centos7");
  script_tag(name:"summary", value:"Check the version of ghostscript");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"The Ghostscript suite contains utilities for
  rendering PostScript and PDF documents. Ghostscript translates PostScript code
  to common bitmap formats so that the code can be displayed or printed.

Security Fix(es):

  * It was discovered that the ghostscript /invalidaccess checks fail under
certain conditions. An attacker could possibly exploit this to bypass the

  - -dSAFER protection and, for example, execute arbitrary shell commands via a
specially crafted PostScript document. (CVE-2018-16509)

  * ghostscript: LockDistillerParams type confusion (699656) (CVE-2018-15910)

  * ghostscript: .definemodifiedfont memory corruption if /typecheck is
handled (699668) (CVE-2018-16542)

  * ghostscript: Stack-based out-of-bounds write in pdf_set_text_matrix
function in gdevpdts.c (CVE-2018-10194)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Tavis Ormandy (Google Project Zero) for
reporting CVE-2018-16509, CVE-2018-15910, and CVE-2018-16542.");
  script_tag(name:"affected", value:"ghostscript on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2918");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-October/023066.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.07~29.el7_5.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-cups", rpm:"ghostscript-cups~9.07~29.el7_5.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.07~29.el7_5.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.07~29.el7_5.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-gtk", rpm:"ghostscript-gtk~9.07~29.el7_5.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
