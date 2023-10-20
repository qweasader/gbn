# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0189");
  script_cve_id("CVE-2018-4919", "CVE-2018-4920");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 16:25:00 +0000 (Fri, 18 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2018-0189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0189");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0189.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22767");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb18-05.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flash-player-plugin' package(s) announced via the MGASA-2018-0189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that flash versions older than 29.0.0.113 contained a use
after free vulnerability that could lead to remote code execution
(CVE-2018-4919).

A second vulnerability was a type confusion which could also lead to
remote code execution (CVE-2018-4920).");

  script_tag(name:"affected", value:"'flash-player-plugin' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"flash-player-plugin", rpm:"flash-player-plugin~29.0.0.113~1.mga6.nonfree", rls:"MAGEIA6"))) {
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
