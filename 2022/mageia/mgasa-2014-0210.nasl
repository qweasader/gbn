# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0210");
  script_cve_id("CVE-2013-7353", "CVE-2013-7354");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0210)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0210");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0210.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00026.html");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00024.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13185");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng, libpng12' package(s) announced via the MGASA-2014-0210 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated libpng12 and libpng packages fix security vulnerabilities:

An integer overflow leading to a heap-based buffer overflow was found in
the png_set_sPLT() and png_set_text_2() API functions of libpng. An
attacker could create a specially-crafted image file and render it with
an application written to explicitly call png_set_sPLT() or
png_set_text_2() function, could cause libpng to crash or execute
arbitrary code with the permissions of the user running such an
application (CVE-2013-7353).

An integer overflow leading to a heap-based buffer overflow was found in
the png_set_unknown_chunks() API function of libpng. An attacker could
create a specially-crafted image file and render it with an application
written to explicitly call png_set_unknown_chunks() function, could cause
libpng to crash or execute arbitrary code with the permissions of the user
running such an application (CVE-2013-7354).");

  script_tag(name:"affected", value:"'libpng, libpng12' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"lib64png-devel", rpm:"lib64png-devel~1.5.13~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png12-devel", rpm:"lib64png12-devel~1.2.50~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png12_0", rpm:"lib64png12_0~1.2.50~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64png15_15", rpm:"lib64png15_15~1.5.13~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.5.13~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.5.13~2.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12", rpm:"libpng12~1.2.50~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12-devel", rpm:"libpng12-devel~1.2.50~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng12_0", rpm:"libpng12_0~1.2.50~3.2.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng15_15", rpm:"libpng15_15~1.5.13~2.2.mga3", rls:"MAGEIA3"))) {
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
