# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120565");
  script_cve_id("CVE-2011-2939", "CVE-2011-3597");
  script_tag(name:"creation_date", value:"2015-09-08 09:29:03 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-07T03:03:10+0000");
  script_tag(name:"last_modification", value:"2022-01-07 03:03:10 +0000 (Fri, 07 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Amazon Linux: Security Advisory (ALAS-2011-19)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2011-19");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2011-19.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the ALAS-2011-19 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A heap-based buffer overflow flaw was found in the way Perl decoded Unicode strings. An attacker could create a malicious Unicode string that, when decoded by a Perl program, would cause the program to crash or, potentially, execute arbitrary code with the permissions of the user running the program. (CVE-2011-2939)

It was found that the 'new' constructor of the Digest module used its argument as part of the string expression passed to the eval() function. An attacker could possibly use this flaw to execute arbitrary Perl code with the privileges of a Perl program that uses untrusted input as an argument to the constructor. (CVE-2011-3597)");

  script_tag(name:"affected", value:"'perl' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"perl", rpm:"perl~5.10.1~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Archive-Extract", rpm:"perl-Archive-Extract~0.38~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Archive-Tar", rpm:"perl-Archive-Tar~1.58~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CGI", rpm:"perl-CGI~3.51~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CPAN", rpm:"perl-CPAN~1.9402~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-CPANPLUS", rpm:"perl-CPANPLUS~0.88~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Compress-Raw-Zlib", rpm:"perl-Compress-Raw-Zlib~2.023~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Compress-Zlib", rpm:"perl-Compress-Zlib~2.020~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Digest-SHA", rpm:"perl-Digest-SHA~5.47~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-CBuilder", rpm:"perl-ExtUtils-CBuilder~0.27~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-Embed", rpm:"perl-ExtUtils-Embed~1.28~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-MakeMaker", rpm:"perl-ExtUtils-MakeMaker~6.55~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-ExtUtils-ParseXS", rpm:"perl-ExtUtils-ParseXS~2.2003.0~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-File-Fetch", rpm:"perl-File-Fetch~0.26~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO-Compress-Base", rpm:"perl-IO-Compress-Base~2.020~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO-Compress-Zlib", rpm:"perl-IO-Compress-Zlib~2.020~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IO-Zlib", rpm:"perl-IO-Zlib~1.09~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-IPC-Cmd", rpm:"perl-IPC-Cmd~0.56~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Locale-Maketext-Simple", rpm:"perl-Locale-Maketext-Simple~0.18~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Log-Message", rpm:"perl-Log-Message~0.02~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Log-Message-Simple", rpm:"perl-Log-Message-Simple~0.04~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Build", rpm:"perl-Module-Build~0.3500~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-CoreList", rpm:"perl-Module-CoreList~2.18~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Load", rpm:"perl-Module-Load~0.16~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Load-Conditional", rpm:"perl-Module-Load-Conditional~0.30~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Loaded", rpm:"perl-Module-Loaded~0.02~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Module-Pluggable", rpm:"perl-Module-Pluggable~3.90~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Object-Accessor", rpm:"perl-Object-Accessor~0.34~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Package-Constants", rpm:"perl-Package-Constants~0.02~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Params-Check", rpm:"perl-Params-Check~0.26~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Parse-CPAN-Meta", rpm:"perl-Parse-CPAN-Meta~1.40~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Pod-Escapes", rpm:"perl-Pod-Escapes~1.04~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Pod-Simple", rpm:"perl-Pod-Simple~3.13~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Term-UI", rpm:"perl-Term-UI~0.20~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Test-Harness", rpm:"perl-Test-Harness~3.17~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Test-Simple", rpm:"perl-Test-Simple~0.92~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Time-HiRes", rpm:"perl-Time-HiRes~1.9721~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Time-Piece", rpm:"perl-Time-Piece~1.15~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-core", rpm:"perl-core~5.10.1~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-debuginfo", rpm:"perl-debuginfo~5.10.1~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-devel", rpm:"perl-devel~5.10.1~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-libs", rpm:"perl-libs~5.10.1~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-parent", rpm:"perl-parent~0.221~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-suidperl", rpm:"perl-suidperl~5.10.1~119.12.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-version", rpm:"perl-version~0.77~119.12.amzn1", rls:"AMAZON"))) {
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
