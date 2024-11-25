# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0457");
  script_cve_id("CVE-2022-45939");
  script_tag(name:"creation_date", value:"2022-12-14 04:11:58 +0000 (Wed, 14 Dec 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-01 19:48:04 +0000 (Thu, 01 Dec 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0457)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0457");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0457.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31211");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MU2KN46JJ6TL6CR5QN3O4AZXDYE35Z7A/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-December/013180.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'emacs' package(s) announced via the MGASA-2022-0457 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU Emacs through 28.2 allows attackers to execute commands via shell
metacharacters in the name of a source-code file, because lib-src/etags.c
uses the system C library function in its implementation of the ctags
program. For example, a victim may use the 'ctags *' command (suggested in
the ctags documentation) in a situation where the current working
directory has contents that depend on untrusted input. (CVE-2022-45939)");

  script_tag(name:"affected", value:"'emacs' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"emacs", rpm:"emacs~27.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-common", rpm:"emacs-common~27.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-doc", rpm:"emacs-doc~27.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-el", rpm:"emacs-el~27.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-leim", rpm:"emacs-leim~27.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"emacs-nox", rpm:"emacs-nox~27.1~1.2.mga8", rls:"MAGEIA8"))) {
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
