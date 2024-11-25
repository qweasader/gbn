# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0408");
  script_cve_id("CVE-2019-15845", "CVE-2019-16201", "CVE-2019-16254", "CVE-2019-16255");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-17 20:10:13 +0000 (Fri, 17 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0408)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0408");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0408.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25564");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/4201-1/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2019/10/01/code-injection-shell-test-cve-2019-16255/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2019/10/01/http-response-splitting-in-webrick-cve-2019-16254/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2019/10/01/nul-injection-file-fnmatch-cve-2019-15845/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2019/10/01/ruby-2-5-7-released/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2019/10/01/webrick-regexp-digestauth-dos-cve-2019-16201/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the MGASA-2019-0408 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ruby packages fix security vulnerabilities:

It was discovered that Ruby incorrectly handled certain files. An attacker
could possibly use this issue to pass path matching what can lead to an
unauthorized access (CVE-2019-15845).

It was discovered that Ruby incorrectly handled certain regular expressions.
An attacker could use this issue to cause a denial of service
(CVE-2019-16201).

It was discovered that Ruby incorrectly handled certain HTTP headers. An
attacker could possibly use this issue to execute arbitrary code
(CVE-2019-16254).

It was discovered that Ruby incorrectly handled certain inputs. An attacker
could possibly use this issue to execute arbitrary code (CVE-2019-16255).");

  script_tag(name:"affected", value:"'ruby' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ruby2.5", rpm:"lib64ruby2.5~2.5.7~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2.5", rpm:"libruby2.5~2.5.7~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby", rpm:"ruby~2.5.7~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~2.5.7~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-did_you_mean", rpm:"ruby-did_you_mean~1.2.0~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-doc", rpm:"ruby-doc~2.5.7~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-io-console", rpm:"ruby-io-console~0.4.6~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-irb", rpm:"ruby-irb~2.5.7~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-net-telnet", rpm:"ruby-net-telnet~0.1.1~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-openssl", rpm:"ruby-openssl~2.1.2~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-power_assert", rpm:"ruby-power_assert~1.1.1~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-psych", rpm:"ruby-psych~3.0.2~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-rake", rpm:"ruby-rake~12.3.0~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-test-unit", rpm:"ruby-test-unit~3.2.7~20.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-xmlrpc", rpm:"ruby-xmlrpc~0.3.0~20.mga7", rls:"MAGEIA7"))) {
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
