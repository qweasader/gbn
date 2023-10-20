# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0002");
  script_cve_id("CVE-2019-14853", "CVE-2019-14859");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-08 18:32:00 +0000 (Tue, 08 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0002)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0002");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0002.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25729");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4196-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-ecdsa' package(s) announced via the MGASA-2020-0002 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-ecdsa packages fix security vulnerabilities:

It was discovered that python-ecdsa incorrectly handled certain signatures.
A remote attacker could possibly use this issue to cause python-ecdsa to
generate unexpected exceptions, resulting in a denial of service
(CVE-2019-14853).

It was discovered that python-ecdsa incorrectly verified DER encoding in
signatures. A remote attacker could use this issue to perform certain
malleability attacks (CVE-2019-14859).");

  script_tag(name:"affected", value:"'python-ecdsa' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-ecdsa", rpm:"python-ecdsa~0.13.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ecdsa", rpm:"python3-ecdsa~0.13.3~1.mga7", rls:"MAGEIA7"))) {
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
