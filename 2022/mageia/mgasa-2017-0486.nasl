# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0486");
  script_cve_id("CVE-2017-17405", "CVE-2017-17790");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-12 14:39:15 +0000 (Fri, 12 Jan 2018)");

  script_name("Mageia: Security Advisory (MGASA-2017-0486)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(5|6)");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0486");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0486.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22203");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2017/12/14/net-ftp-command-injection-cve-2017-17405/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the MGASA-2017-0486 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ruby before 2.4.3 allows Net::FTP command injection. Net::FTP#get,
getbinaryfile, gettextfile, put, putbinaryfile, and puttextfile use
Kernel#open to open a local file. If the localfile argument starts with
the '<pipe>' pipe character, the command following the pipe character is
executed. The default value of localfile is File.basename(remotefile),
so malicious FTP servers could cause arbitrary command execution
(CVE-2017-17405).

The lazy_initialize function in lib/resolv.rb in Ruby through 2.4.3 uses
Kernel#open, which might allow Command Injection attacks, as
demonstrated by a Resolv::Hosts::new argument beginning with a '<pipe>'
character (CVE-2017-17790).");

  script_tag(name:"affected", value:"'ruby' package(s) on Mageia 5, Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby2.0", rpm:"lib64ruby2.0~2.0.0.p648~1.6.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2.0", rpm:"libruby2.0~2.0.0.p648~1.6.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.0.0.p648~1.6.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~2.0.0.p648~1.6.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~2.0.0.p648~1.6.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.0.0.p648~1.6.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~2.0.0.p648~1.6.mga5", rls:"MAGEIA5"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby2.2", rpm:"lib64ruby2.2~2.2.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2.2", rpm:"libruby2.2~2.2.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.2.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~2.2.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~2.2.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-io-console", rpm:"ruby-io-console~0.4.3~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.2.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-power_assert", rpm:"ruby-power_assert~0.2.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-test-unit", rpm:"ruby-test-unit~3.0.8~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-tk", rpm:"ruby-tk~2.2.8~1.1.mga6", rls:"MAGEIA6"))) {
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
