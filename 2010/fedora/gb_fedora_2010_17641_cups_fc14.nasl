# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2010-November/050977.html");
  script_oid("1.3.6.1.4.1.25623.1.0.862590");
  script_version("2023-06-30T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-06-30 05:06:12 +0000 (Fri, 30 Jun 2023)");
  script_tag(name:"creation_date", value:"2010-12-02 08:39:14 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name:"FEDORA", value:"2010-17641");
  script_cve_id("CVE-2010-2941");
  script_name("Fedora Update for cups FEDORA-2010-17641");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC14");
  script_tag(name:"affected", value:"cups on Fedora 14");
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

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"cups", rpm:"cups~1.4.4~11.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}