# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.872863");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-07-14 15:55:08 +0530 (Fri, 14 Jul 2017)");
  script_cve_id("CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009",
                "CVE-2017-5010", "CVE-2017-5011", "CVE-2017-5012", "CVE-2017-5013",
                "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5016", "CVE-2017-5017",
                "CVE-2017-5018", "CVE-2017-5019", "CVE-2017-5020", "CVE-2017-5021",
                "CVE-2017-5022", "CVE-2017-5023", "CVE-2017-5024", "CVE-2017-5025",
                "CVE-2017-5026", "CVE-2017-5027", "CVE-2017-5029", "CVE-2017-5032",
                "CVE-2017-5033", "CVE-2017-5034", "CVE-2017-5036", "CVE-2017-5039",
                "CVE-2017-5040", "CVE-2017-5044", "CVE-2017-5045", "CVE-2017-5046",
                "CVE-2017-5052", "CVE-2017-5053", "CVE-2017-5055", "CVE-2017-5057",
                "CVE-2017-5058", "CVE-2017-5059", "CVE-2017-5060", "CVE-2017-5061",
                "CVE-2017-5062", "CVE-2017-5065", "CVE-2017-5066", "CVE-2017-5067",
                "CVE-2017-5068", "CVE-2017-5069");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-11 19:17:00 +0000 (Mon, 11 Apr 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for qt5-qtwebengine FEDORA-2017-58cde32413");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"qt5-qtwebengine on Fedora 25");
  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"FEDORA", value:"2017-58cde32413");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YRHOZIPAIWULMGZJKJAYNTQUNKQAMBVN");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC25");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.9.0~4.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
