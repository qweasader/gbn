# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_tag(name:"affected", value:"java-1.6.0-openjdk on Fedora 16");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2013-February/098442.html");
  script_oid("1.3.6.1.4.1.25623.1.0.865329");
  script_version("2023-06-22T10:34:15+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:15 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-02-11 10:08:12 +0530 (Mon, 11 Feb 2013)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0424", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427",
                "CVE-2013-0429", "CVE-2013-0432", "CVE-2013-0443", "CVE-2013-0440",
                "CVE-2013-0442", "CVE-2013-0428", "CVE-2013-0441", "CVE-2013-0435",
                "CVE-2013-0433", "CVE-2013-0450", "CVE-2013-1475", "CVE-2013-1476",
                "CVE-2013-0434", "CVE-2013-1478", "CVE-2013-1480", "CVE-2011-3571",
                "CVE-2011-3563", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505",
                "CVE-2012-0506", "CVE-2012-0497", "CVE-2012-0501", "CVE-2011-5035",
                "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552",
                "CVE-2011-3544", "CVE-2011-3521", "CVE-2011-3554", "CVE-2011-3389",
                "CVE-2011-3558", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3560");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"FEDORA", value:"2013-2197");
  script_name("Fedora Update for java-1.6.0-openjdk FEDORA-2013-2197");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1.6.0-openjdk'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC16");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC16")
{

  if ((res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~71.1.11.6.fc16", rls:"FC16")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
