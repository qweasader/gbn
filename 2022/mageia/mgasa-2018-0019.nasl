# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0019");
  script_cve_id("CVE-2017-8373", "CVE-2017-8374");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-12 13:27:11 +0000 (Fri, 12 May 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0019)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0019");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0019.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/05/01/8");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2017/05/01/9");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20773");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2017-8373");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/CVE-2017-8374");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mad' package(s) announced via the MGASA-2018-0019 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The mad_layer_III function in layer3.c in Underbit MAD libmad 0.15.1b
allows remote attackers to cause a denial of service (heap-based buffer
overflow and application crash) or possibly have unspecified other impact
via a crafted audio file (CVE-2017-8373).

The mad_bit_skip function in bit.c in Underbit MAD libmad 0.15.1b allows
remote attackers to cause a denial of service (heap-based buffer over-read
and application crash) via a crafted audio file (CVE-2017-8374).");

  script_tag(name:"affected", value:"'mad' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64mad-devel", rpm:"lib64mad-devel~0.15.1b~17.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mad0", rpm:"lib64mad0~0.15.1b~17.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmad-devel", rpm:"libmad-devel~0.15.1b~17.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmad0", rpm:"libmad0~0.15.1b~17.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mad", rpm:"mad~0.15.1b~17.4.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64mad-devel", rpm:"lib64mad-devel~0.15.1b~22.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64mad0", rpm:"lib64mad0~0.15.1b~22.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmad-devel", rpm:"libmad-devel~0.15.1b~22.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmad0", rpm:"libmad0~0.15.1b~22.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mad", rpm:"mad~0.15.1b~22.1.mga6", rls:"MAGEIA6"))) {
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
