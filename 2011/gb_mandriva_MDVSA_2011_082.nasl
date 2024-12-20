# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-05/msg00002.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831385");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-06 16:22:00 +0200 (Fri, 06 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name:"MDVSA", value:"2011:082");
  script_cve_id("CVE-2009-5065", "CVE-2011-1156", "CVE-2011-1157", "CVE-2011-1158");
  script_name("Mandriva Update for python-feedparser MDVSA-2011:082 (python-feedparser)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-feedparser'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_(2010\.1|2010\.0)");
  script_tag(name:"affected", value:"python-feedparser on Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64");
  script_tag(name:"insight", value:"Multiple vulnerabilities has been found and corrected in
  python-feedparser:

  Cross-site scripting (XSS) vulnerability in feedparser.py in Universal
  Feed Parser (aka feedparser or python-feedparser) before 5.0 allows
  remote attackers to inject arbitrary web script or HTML via vectors
  involving nested CDATA stanzas (CVE-2009-5065).

  feedparser.py in Universal Feed Parser (aka feedparser or
  python-feedparser) before 5.0.1 allows remote attackers to cause
  a denial of service (application crash) via a malformed DOCTYPE
  declaration (CVE-2011-1156).

  Cross-site scripting (XSS) vulnerability in feedparser.py in Universal
  Feed Parser (aka feedparser or python-feedparser) 5.x before 5.0.1
  allows remote attackers to inject arbitrary web script or HTML via
  malformed XML comments (CVE-2011-1157).

  Cross-site scripting (XSS) vulnerability in feedparser.py in Universal
  Feed Parser (aka feedparser or python-feedparser) 5.x before 5.0.1
  allows remote attackers to inject arbitrary web script or HTML
  via an unexpected URI scheme, as demonstrated by a javascript: URI
  (CVE-2011-1158).

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

if(release == "MNDK_2010.1")
{

  if ((res = isrpmvuln(pkg:"python-feedparser", rpm:"python-feedparser~4.1~8.1mdv2010.2", rls:"MNDK_2010.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "MNDK_2010.0")
{

  if ((res = isrpmvuln(pkg:"python-feedparser", rpm:"python-feedparser~4.1~7.1mdv2010.0", rls:"MNDK_2010.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
