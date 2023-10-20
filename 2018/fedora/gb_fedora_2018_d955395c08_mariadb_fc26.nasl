# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.874594");
  script_version("2023-06-28T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-28 05:05:22 +0000 (Wed, 28 Jun 2023)");
  script_tag(name:"creation_date", value:"2018-05-23 05:50:35 +0200 (Wed, 23 May 2018)");
  script_cve_id("CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2771",
                "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787",
                "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819", "CVE-2017-3265",
                "CVE-2017-3313", "CVE-2017-3308", "CVE-2017-3309", "CVE-2017-3453",
                "CVE-2017-3456", "CVE-2017-3464", "CVE-2018-2773", "CVE-2018-2818");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 16:40:00 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for mariadb FEDORA-2018-d955395c08");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
on the target host.");
  script_tag(name:"affected", value:"mariadb on Fedora 26");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-d955395c08");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/C7UF6XVJNCHPSN5BBYHUX267XZGFVP5P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC26");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC26")
{

  if ((res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.1.33~1.fc26", rls:"FC26")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
