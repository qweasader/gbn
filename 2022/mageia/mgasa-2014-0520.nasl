# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0520");
  script_cve_id("CVE-2014-9157");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mageia: Security Advisory (MGASA-2014-0520)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0520");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0520.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14756");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-December/145217.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'graphviz' package(s) announced via the MGASA-2014-0520 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated graphviz packages fix security vulnerability:

Format string vulnerability in the yyerror function in lib/cgraph/scan.l in
Graphviz allows remote attackers to have unspecified impact via format string
specifiers in unknown vector, which are not properly handled in an error
string (CVE-2014-9157).");

  script_tag(name:"affected", value:"'graphviz' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"graphviz", rpm:"graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"graphviz-doc", rpm:"graphviz-doc~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-graphviz", rpm:"java-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cdt5", rpm:"lib64cdt5~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64cgraph6", rpm:"lib64cgraph6~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64graphviz-devel", rpm:"lib64graphviz-devel~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gvc6", rpm:"lib64gvc6~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gvpr2", rpm:"lib64gvpr2~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64pathplan4", rpm:"lib64pathplan4~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xdot4", rpm:"lib64xdot4~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcdt5", rpm:"libcdt5~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcgraph6", rpm:"libcgraph6~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgraphviz-devel", rpm:"libgraphviz-devel~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvc6", rpm:"libgvc6~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgvpr2", rpm:"libgvpr2~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpathplan4", rpm:"libpathplan4~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxdot4", rpm:"libxdot4~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lua-graphviz", rpm:"lua-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-graphviz", rpm:"ocaml-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-graphviz", rpm:"perl-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-graphviz", rpm:"php-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-graphviz", rpm:"python-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-graphviz", rpm:"ruby-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tcl-graphviz", rpm:"tcl-graphviz~2.34.0~6.1.mga4", rls:"MAGEIA4"))) {
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
