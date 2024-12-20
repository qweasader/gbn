# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-June/015957.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880820");
  script_version("2024-01-01T05:05:52+0000");
  script_tag(name:"last_modification", value:"2024-01-01 05:05:52 +0000 (Mon, 01 Jan 2024)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 15:21:00 +0000 (Thu, 28 Dec 2023)");
  script_xref(name:"CESA", value:"2009:1083");
  script_cve_id("CVE-2009-0791", "CVE-2009-0949", "CVE-2009-1196");
  script_name("CentOS Update for cups CESA-2009:1083 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"cups on CentOS 3");
  script_tag(name:"insight", value:"The Common UNIX Printing System (CUPS) provides a portable printing layer
  for UNIX operating systems. The Internet Printing Protocol (IPP) allows
  users to print and manage printing-related tasks over a network. The CUPS
  'pdftops' filter converts Portable Document Format (PDF) files to
  PostScript. 'pdftops' is based on Xpdf and the CUPS imaging library.

  A NULL pointer dereference flaw was found in the CUPS IPP routine, used for
  processing incoming IPP requests for the CUPS scheduler. An attacker could
  use this flaw to send specially-crafted IPP requests that would crash the
  cupsd daemon. (CVE-2009-0949)

  A use-after-free flaw was found in the CUPS scheduler directory services
  routine, used to process data about available printers and printer classes.
  An attacker could use this flaw to cause a denial of service (cupsd daemon
  stop or crash). (CVE-2009-1196)

  Multiple integer overflows flaws, leading to heap-based buffer overflows,
  were found in the CUPS 'pdftops' filter. An attacker could create a
  malicious PDF file that would cause 'pdftops' to crash or, potentially,
  execute arbitrary code as the 'lp' user if the file was printed.
  (CVE-2009-0791)

  Red Hat would like to thank Anibal Sacco from Core Security Technologies
  for reporting the CVE-2009-0949 flaw, and Swen van Brussel for reporting
  the CVE-2009-1196 flaw.

  Users of cups are advised to upgrade to these updated packages, which
  contain backported patches to correct these issues. After installing this
  update, the cupsd daemon will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.1.17~13.3.62", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-devel", rpm:"cups-devel~1.1.17~13.3.62", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cups-libs", rpm:"cups-libs~1.1.17~13.3.62", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
