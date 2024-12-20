# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0049");
  script_cve_id("CVE-2018-11499", "CVE-2018-19797", "CVE-2018-19827", "CVE-2018-19837", "CVE-2018-19838", "CVE-2018-19839", "CVE-2018-20190", "CVE-2018-20821", "CVE-2018-20822", "CVE-2019-6283", "CVE-2019-6284", "CVE-2019-6286");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-28 13:32:43 +0000 (Thu, 28 Jun 2018)");

  script_name("Mageia: Security Advisory (MGASA-2020-0049)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0049");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0049.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25755");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-07/msg00119.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsass' package(s) announced via the MGASA-2020-0049 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use-after-free vulnerability in sass_context.cpp:handle_error
(CVE-2018-11499).

Null pointer dereference in Sass::Selector_List::populate_extends
(CVE-2018-19797).

Use-after-free vulnerability exists in the SharedPtr class
(CVE-2018-19827).

Stack overflow in Eval::operator() (CVE-2018-19837).

Stack-overflow at IMPLEMENT_AST_OPERATORS expansion (CVE-2018-19838).

Buffer-overflow (OOB read) against some invalid input (CVE-2018-19839).

Null pointer dereference in Sass::Eval::operator()
(Sass::Supports_Operator*)
(CVE-2018-20190).

Uncontrolled recursion in Sass:Parser:parse_css_variable_value
(CVE-2018-20821).

Stack-overflow at Sass::Inspect::operator() (CVE-2018-20822).

Heap-buffer-overflow in Sass::Prelexer::parenthese_scope(char const*)
(CVE-2019-6283).

Heap-based buffer over-read exists in Sass:Prelexer:alternatives
(CVE-2019-6284).

Heap-based buffer over-read exists in Sass:Prelexer:skip_over_scopes
(CVE-2019-6286).");

  script_tag(name:"affected", value:"'libsass' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64sass-devel", rpm:"lib64sass-devel~3.6.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64sass0", rpm:"lib64sass0~3.6.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsass", rpm:"libsass~3.6.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsass-devel", rpm:"libsass-devel~3.6.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsass0", rpm:"libsass0~3.6.1~1.mga7", rls:"MAGEIA7"))) {
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
