# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_xref(name:"URL", value:"http://lists.fedoraproject.org/pipermail/package-announce/2011-November/070272.html");
  script_oid("1.3.6.1.4.1.25623.1.0.863647");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"creation_date", value:"2011-12-02 13:22:20 +0530 (Fri, 02 Dec 2011)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:59:00 +0000 (Fri, 31 Jul 2020)");
  script_xref(name:"FEDORA", value:"2011-16346");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2011-4110", "CVE-2011-4326", "CVE-2011-4132", "CVE-2011-4081",
                "CVE-2011-4077", "CVE-2011-1083", "CVE-2011-2699", "CVE-2011-1161",
                "CVE-2011-3353", "CVE-2011-2918", "CVE-2011-3188", "CVE-2011-2723",
                "CVE-2011-2928", "CVE-2011-3191", "CVE-2011-1833", "CVE-2011-2905",
                "CVE-2011-2695", "CVE-2011-2497", "CVE-2011-2517", "CVE-2011-1770",
                "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1745", "CVE-2011-1746",
                "CVE-2010-4668", "CVE-2010-4073", "CVE-2010-4072", "CVE-2010-3880",
                "CVE-2010-2962", "CVE-2010-3698", "CVE-2010-2963", "CVE-2010-3904");
  script_name("Fedora Update for kernel FEDORA-2011-16346");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC14");
  script_tag(name:"affected", value:"kernel on Fedora 14");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.35.14~106.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
