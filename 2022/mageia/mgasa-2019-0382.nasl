# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0382");
  script_cve_id("CVE-2019-12523", "CVE-2019-12526", "CVE-2019-18676", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-11 00:15:00 +0000 (Sat, 11 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0382)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0382");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0382.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25812");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_7.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_8.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_9.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_10.txt");
  script_xref(name:"URL", value:"http://www.squid-cache.org/Advisories/SQUID-2019_11.txt");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-11/msg00119.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2019-0382 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Potential remote code execution during URN processing (CVE-2019-12526).

Multiple improper validations in URI processing (CVE-2019-12523,
CVE-2019-18676).

Cross-Site Request Forgery in HTTP Request processing (CVE-2019-18677).

Incorrect message parsing which could have led to HTTP request splitting
issue (CVE-2019-18678).

Information disclosure when processing HTTP Digest Authentication
(CVE-2019-18679).");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~4.9~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~4.9~1.mga7", rls:"MAGEIA7"))) {
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
