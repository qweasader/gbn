# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0033");
  script_cve_id("CVE-2013-6402", "CVE-2013-6427");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0033)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0033");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0033.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11809");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=725876");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/hplip/+bug/1048754");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hplip' package(s) announced via the MGASA-2014-0033 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the HPLIP Polkit daemon incorrectly handled
temporary files. A local attacker could possibly use this issue to
overwrite arbitrary files. (CVE-2013-6402)

It was discovered that HPLIP contained an upgrade tool that would download
code in an unsafe fashion. If a remote attacker were able to perform a
man-in-the-middle attack, this flaw could be exploited to execute arbitrary
code. (CVE-2013-6427)

Additionally, this update should fix issues regarding wireless connection
to printer hplip after 3.12.9 and prior to version 3.12.11 had issues with
setting up wireless connection to printers due to internal code changes
which had not been applied consistently.");

  script_tag(name:"affected", value:"'hplip' package(s) on Mageia 3.");

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

  if(!isnull(res = isrpmvuln(pkg:"hplip", rpm:"hplip~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-doc", rpm:"hplip-doc~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-gui", rpm:"hplip-gui~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs", rpm:"hplip-hpijs~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-hpijs-ppds", rpm:"hplip-hpijs-ppds~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hplip-model-data", rpm:"hplip-model-data~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0", rpm:"lib64hpip0~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hpip0-devel", rpm:"lib64hpip0-devel~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sane-hpaio1", rpm:"lib64sane-hpaio1~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0", rpm:"libhpip0~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhpip0-devel", rpm:"libhpip0-devel~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsane-hpaio1", rpm:"libsane-hpaio1~3.12.9~6.3.mga3", rls:"MAGEIA3"))) {
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
