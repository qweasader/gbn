# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0343");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2015-0343)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(4|5)");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0343");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0343.html");
  script_xref(name:"URL", value:"http://vcs.pcre.org/pcre/code/trunk/ChangeLog?revision=1600&view=markup");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16067");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pcre' package(s) announced via the MGASA-2015-0343 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated pcre packages fix security vulnerabilities:

The pcre package has been updated to the latest CVS as of September 2, 2015,
aka 8.38-RC1, which fixes several bugs, including many buffer, stack, and
integer overflows.");

  script_tag(name:"affected", value:"'pcre' package(s) on Mageia 4, Mageia 5.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre-devel", rpm:"lib64pcre-devel~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre1", rpm:"lib64pcre1~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre16_0", rpm:"lib64pcre16_0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre32_0", rpm:"lib64pcre32_0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp-devel", rpm:"lib64pcrecpp-devel~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp0", rpm:"lib64pcrecpp0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix-devel", rpm:"lib64pcreposix-devel~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix0", rpm:"lib64pcreposix0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix1", rpm:"lib64pcreposix1~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre-devel", rpm:"libpcre-devel~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16_0", rpm:"libpcre16_0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre32_0", rpm:"libpcre32_0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp-devel", rpm:"libpcrecpp-devel~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix-devel", rpm:"libpcreposix-devel~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix1", rpm:"libpcreposix1~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.37~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre-devel", rpm:"lib64pcre-devel~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre1", rpm:"lib64pcre1~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre16_0", rpm:"lib64pcre16_0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcre32_0", rpm:"lib64pcre32_0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp-devel", rpm:"lib64pcrecpp-devel~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcrecpp0", rpm:"lib64pcrecpp0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix-devel", rpm:"lib64pcreposix-devel~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix0", rpm:"lib64pcreposix0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pcreposix1", rpm:"lib64pcreposix1~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre-devel", rpm:"libpcre-devel~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre1", rpm:"libpcre1~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre16_0", rpm:"libpcre16_0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcre32_0", rpm:"libpcre32_0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp-devel", rpm:"libpcrecpp-devel~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcrecpp0", rpm:"libpcrecpp0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix-devel", rpm:"libpcreposix-devel~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix0", rpm:"libpcreposix0~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpcreposix1", rpm:"libpcreposix1~8.37~2.2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pcre", rpm:"pcre~8.37~2.2.mga5", rls:"MAGEIA5"))) {
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
