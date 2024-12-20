# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-March/015696.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880806");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:0345");
  script_cve_id("CVE-2009-0583", "CVE-2009-0584");
  script_name("CentOS Update for ghostscript CESA-2009:0345 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"ghostscript on CentOS 3");
  script_tag(name:"insight", value:"Ghostscript is a set of software that provides a PostScript(TM)
  interpreter, a set of C procedures (the Ghostscript library, which
  implements the graphics capabilities in the PostScript language) and
  an interpreter for Portable Document Format (PDF) files.

  Multiple integer overflow flaws which could lead to heap-based buffer
  overflows, as well as multiple insufficient input validation flaws, were
  found in Ghostscript's International Color Consortium Format library
  (icclib). Using specially-crafted ICC profiles, an attacker could create a
  malicious PostScript or PDF file with embedded images which could cause
  Ghostscript to crash, or, potentially, execute arbitrary code when opened
  by the victim. (CVE-2009-0583, CVE-2009-0584)

  All users of ghostscript are advised to upgrade to these updated packages,
  which contain a backported patch to correct these issues.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~7.05~32.1.17", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~7.05~32.1.17", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hpijs", rpm:"hpijs~1.3~32.1.17", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
