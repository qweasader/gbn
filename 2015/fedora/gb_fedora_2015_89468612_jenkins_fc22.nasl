# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806920");
  script_version("2023-05-18T09:08:59+0000");
  script_tag(name:"last_modification", value:"2023-05-18 09:08:59 +0000 (Thu, 18 May 2023)");
  script_tag(name:"creation_date", value:"2015-12-23 05:38:34 +0100 (Wed, 23 Dec 2015)");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-5317", "CVE-2015-5319", "CVE-2015-5324", "CVE-2015-5321",
                "CVE-2015-5322", "CVE-2015-5323", "CVE-2015-5326");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for jenkins FEDORA-2015-89468612");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'jenkins'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"jenkins on Fedora 22");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2015-89468612");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-December/174273.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC22");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC22")
{
  if ((res = isrpmvuln(pkg:"jenkins", rpm:"jenkins~1.609.3~4.fc22", rls:"FC22")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }
  if (__pkg_match) exit(99);
  exit(0);
}
