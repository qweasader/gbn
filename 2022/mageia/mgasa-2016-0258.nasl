# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0258");
  script_cve_id("CVE-2016-6132", "CVE-2016-6207", "CVE-2016-6214");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-12 15:59:04 +0000 (Fri, 12 Aug 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0258)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0258");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0258.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/06/30/10");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/12/4");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/07/13/12");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18938");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18947");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=72558");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgd' package(s) announced via the MGASA-2016-0258 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libgd packages fix security vulnerabilities:

A read out-of-bounds was found in the parsing of TGA files when the header
reports an incorrect size (CVE-2016-6132) or invalid bpp (CVE-2016-6214) or
RLE value (upstream issue 248).

Integer overflow error within _gdContributionsAlloc() (CVE-2016-6207).

A regression in the previous update that caused some packages to fail to
build against libgd has also been fixed (mga#18947).");

  script_tag(name:"affected", value:"'libgd' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gd-utils", rpm:"gd-utils~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd-devel", rpm:"lib64gd-devel~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd-static-devel", rpm:"lib64gd-static-devel~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gd3", rpm:"lib64gd3~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd", rpm:"libgd~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd-devel", rpm:"libgd-devel~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd-static-devel", rpm:"libgd-static-devel~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgd3", rpm:"libgd3~2.2.3~1.1.mga5", rls:"MAGEIA5"))) {
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
