# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0166");
  script_cve_id("CVE-2018-18444");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-23 20:15:00 +0000 (Mon, 23 Sep 2019)");

  script_name("Mageia: Security Advisory (MGASA-2019-0166)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0166");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0166.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24759");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-04/msg00178.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr' package(s) announced via the MGASA-2019-0166 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openexr package fixes security vulnerabilities:

It was discovered that makeMultiView.cpp in exrmultiview in OpenEXR
2.3.0 has an out-of-bounds write, leading to an assertion failure or
possibly unspecified other impact (CVE-2018-18444).");

  script_tag(name:"affected", value:"'openexr' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ilmimf2_2_22", rpm:"lib64ilmimf2_2_22~2.2.0~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openexr-devel", rpm:"lib64openexr-devel~2.2.0~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libilmimf2_2_22", rpm:"libilmimf2_2_22~2.2.0~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenexr-devel", rpm:"libopenexr-devel~2.2.0~10.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openexr", rpm:"openexr~2.2.0~10.1.mga6", rls:"MAGEIA6"))) {
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
