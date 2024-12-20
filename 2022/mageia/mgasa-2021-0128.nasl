# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0128");
  script_cve_id("CVE-2021-3410");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-01 16:47:27 +0000 (Mon, 01 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0128)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(7|8)");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0128");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0128.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28556");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2584");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcaca' package(s) announced via the MGASA-2021-0128 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow issue in caca_resize function in libcaca/caca/canvas.c may
lead to local execution of arbitrary code in the user context (CVE-2021-3410).");

  script_tag(name:"affected", value:"'libcaca' package(s) on Mageia 7, Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca-devel", rpm:"lib64caca-devel~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca0", rpm:"lib64caca0~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca", rpm:"libcaca~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0", rpm:"libcaca0~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-caca", rpm:"python-caca~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-caca", rpm:"ruby-caca~0.99~0.beta19.3.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca-devel", rpm:"lib64caca-devel~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64caca0", rpm:"lib64caca0~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca", rpm:"libcaca~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca0", rpm:"libcaca0~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-caca", rpm:"python3-caca~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-caca", rpm:"ruby-caca~0.99~0.beta19.5.1.mga8", rls:"MAGEIA8"))) {
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
