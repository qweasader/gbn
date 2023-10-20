# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0369");
  script_cve_id("CVE-2020-2934");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 12:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0369");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0369.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26522");
  script_xref(name:"URL", value:"https://dev.mysql.com/doc/relnotes/connector-j/8.0/en/news-8-0-20.html");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixMSQL");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/4QDR2WOUETBT76WAO5NNCCXSAM3AGG3D/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-connector-java' package(s) announced via the MGASA-2020-0369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the mysql-connector-java package. A complicated attack
against the mysql Connector/J allows attackers on the local network to
interfere with a user's connection and insert unauthorized SQL commands
(CVE-2020-2934).");

  script_tag(name:"affected", value:"'mysql-connector-java' package(s) on Mageia 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"mysql-connector-java", rpm:"mysql-connector-java~8.0.20~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
