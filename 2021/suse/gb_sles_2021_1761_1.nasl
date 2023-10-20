# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1761.1");
  script_cve_id("CVE-2021-3504");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:37 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-21 18:35:00 +0000 (Mon, 21 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1761-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1761-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211761-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hivex' package(s) announced via the SUSE-SU-2021:1761-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hivex fixes the following issues:

CVE-2021-3504: hivex: missing bounds check within hivex_open()
 (bsc#1185013)");

  script_tag(name:"affected", value:"'hivex' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Development Tools 15-SP2, SUSE Linux Enterprise Module for Development Tools 15-SP3, SUSE MicroOS 5.0.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"hivex-debuginfo", rpm:"hivex-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-debugsource", rpm:"hivex-debugsource~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-devel", rpm:"hivex-devel~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhivex0", rpm:"libhivex0~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhivex0-debuginfo", rpm:"libhivex0-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Win-Hivex", rpm:"perl-Win-Hivex~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Win-Hivex-debuginfo", rpm:"perl-Win-Hivex-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex", rpm:"ocaml-hivex~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex-debuginfo", rpm:"ocaml-hivex-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex-devel", rpm:"ocaml-hivex-devel~1.3.14~5.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"hivex-debuginfo", rpm:"hivex-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-debugsource", rpm:"hivex-debugsource~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hivex-devel", rpm:"hivex-devel~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhivex0", rpm:"libhivex0~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhivex0-debuginfo", rpm:"libhivex0-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Win-Hivex", rpm:"perl-Win-Hivex~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Win-Hivex-debuginfo", rpm:"perl-Win-Hivex-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex", rpm:"ocaml-hivex~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex-debuginfo", rpm:"ocaml-hivex-debuginfo~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-hivex-devel", rpm:"ocaml-hivex-devel~1.3.14~5.3.1", rls:"SLES15.0SP3"))) {
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
