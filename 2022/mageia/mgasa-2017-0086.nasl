# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0086");
  script_cve_id("CVE-2016-10167", "CVE-2016-10168", "CVE-2016-9317");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-16 18:31:20 +0000 (Thu, 16 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0086");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0086.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20474");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwmf' package(s) announced via the MGASA-2017-0086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The gdImageCreate function in the GD Graphics Library (aka libgd) before
2.2.4 allows remote attackers to cause a denial of service (system hang)
via an oversized image. (CVE-2016-9317)

The gdImageCreateFromGd2Ctx function in gd_gd2.c in the GD Graphics
Library (aka libgd) before 2.2.4 allows remote attackers to cause a denial
of service (application crash) via a crafted image file. (CVE-2016-10167)

Integer overflow in gd_io.c in the GD Graphics Library (aka libgd) before
2.2.4 allows remote attackers to have unspecified impact via vectors
involving the number of horizontal and vertical chunks in an image.
(CVE-2016-10168)");

  script_tag(name:"affected", value:"'libwmf' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64wmf-devel", rpm:"lib64wmf-devel~0.2.8.4~32.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64wmf0.2_7", rpm:"lib64wmf0.2_7~0.2.8.4~32.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf", rpm:"libwmf~0.2.8.4~32.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf-devel", rpm:"libwmf-devel~0.2.8.4~32.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwmf0.2_7", rpm:"libwmf0.2_7~0.2.8.4~32.4.mga5", rls:"MAGEIA5"))) {
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
