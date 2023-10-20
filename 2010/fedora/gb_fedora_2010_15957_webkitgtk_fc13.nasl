# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2010-October/049604.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862465");
  script_version("2023-06-30T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-30 16:09:17 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-10-22 16:42:09 +0200 (Fri, 22 Oct 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2010-15957");
  script_cve_id("CVE-2010-1407", "CVE-2010-1405", "CVE-2010-1664", "CVE-2010-1421", "CVE-2010-1807", "CVE-2010-1760", "CVE-2010-1422", "CVE-2010-1665", "CVE-2010-1771", "CVE-2010-2648", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1780", "CVE-2010-1782", "CVE-2010-1788", "CVE-2010-1762", "CVE-2010-1386", "CVE-2010-2264", "CVE-2010-1761", "CVE-2010-3259", "CVE-2010-1416", "CVE-2010-1417", "CVE-2010-1418", "CVE-2010-1770", "CVE-2010-1773", "CVE-2010-3257", "CVE-2010-1774", "CVE-2010-1759", "CVE-2010-1767", "CVE-2010-3113", "CVE-2010-3116", "CVE-2010-3115", "CVE-2010-3114", "CVE-2010-1758", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-1812", "CVE-2010-1793", "CVE-2010-1792", "CVE-2010-1790", "CVE-2010-1772", "CVE-2010-1392");
  script_name("Fedora Update for webkitgtk FEDORA-2010-15957");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkitgtk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC13");
  script_tag(name:"affected", value:"webkitgtk on Fedora 13");
  script_tag(name:"solution", value:"Please install the updated package(s).");
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

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"webkitgtk", rpm:"webkitgtk~1.2.5~1.fc13", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
