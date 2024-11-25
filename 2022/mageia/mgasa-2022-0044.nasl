# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0044");
  script_cve_id("CVE-2022-21658");
  script_tag(name:"creation_date", value:"2022-02-09 07:40:33 +0000 (Wed, 09 Feb 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 17:55:40 +0000 (Mon, 31 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0044)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0044");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0044.html");
  script_xref(name:"URL", value:"https://blog.rust-lang.org/2021/12/02/Rust-1.57.0.html");
  script_xref(name:"URL", value:"https://blog.rust-lang.org/2022/01/20/cve-2022-21658.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29912");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust' package(s) announced via the MGASA-2022-0044 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides Rust 1.57.0 as a feature and bugfix update. See the
release notes for details.

The 'std::fs::remove_dir_all' standard library function was vulnerable a race
condition enabling symlink following (CWE-363). An attacker could use this
security issue to trick a privileged program into deleting files and
directories the attacker couldn't otherwise access or delete (CVE-2022-21658).
This vulnerability was fixed by patching Rust 1.57.0.");

  script_tag(name:"affected", value:"'rust' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"cargo", rpm:"cargo~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-doc", rpm:"cargo-doc~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy", rpm:"clippy~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rls", rpm:"rls~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust", rpm:"rust~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-analysis", rpm:"rust-analysis~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debugger-common", rpm:"rust-debugger-common~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-doc", rpm:"rust-doc~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gdb", rpm:"rust-gdb~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lldb", rpm:"rust-lldb~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-src", rpm:"rust-src~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static", rpm:"rust-std-static~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt", rpm:"rustfmt~1.57.0~1.1.mga8", rls:"MAGEIA8"))) {
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
