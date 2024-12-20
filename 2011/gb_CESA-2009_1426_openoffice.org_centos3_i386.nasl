# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-September/016121.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880752");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1426");
  script_cve_id("CVE-2009-0200", "CVE-2009-0201");
  script_name("CentOS Update for openoffice.org CESA-2009:1426 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openoffice.org'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"openoffice.org on CentOS 3");
  script_tag(name:"insight", value:"OpenOffice.org is an office productivity suite that includes desktop
  applications, such as a word processor, spreadsheet, presentation manager,
  formula editor, and a drawing program.

  An integer underflow flaw and a boundary error flaw, both possibly leading
  to a heap-based buffer overflow, were found in the way OpenOffice.org
  parses certain records in Microsoft Word documents. An attacker could
  create a specially-crafted Microsoft Word document, which once opened by an
  unsuspecting user, could cause OpenOffice.org to crash or, potentially,
  execute arbitrary code with the permissions of the user running
  OpenOffice.org. (CVE-2009-0200, CVE-2009-0201)

  All users of OpenOffice.org are advised to upgrade to these updated
  packages, which contain backported patches to correct these issues. All
  running instances of OpenOffice.org applications must be restarted for
  this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"openoffice.org", rpm:"openoffice.org~1.1.2~44.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-i18n", rpm:"openoffice.org-i18n~1.1.2~44.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openoffice.org-libs", rpm:"openoffice.org-libs~1.1.2~44.2.0.EL3", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
