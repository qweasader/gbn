# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.0002.1");
  script_cve_id("CVE-2017-14919", "CVE-2017-15896", "CVE-2017-3735", "CVE-2017-3736", "CVE-2017-3737", "CVE-2017-3738");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:49 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:01:00 +0000 (Tue, 16 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:0002-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:0002-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20180002-1/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/vulnerability/december-2017-security-releases/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v4.8.7/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v4.8.6/");
  script_xref(name:"URL", value:"https://nodejs.org/en/blog/release/v4.8.5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs4' package(s) announced via the SUSE-SU-2018:0002-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs4 fixes the following issues:
Security issues fixed:
- CVE-2017-15896: Vulnerable to CVE-2017-3737 due to embedded OpenSSL
 (bsc#1072322).
- CVE-2017-14919: Embedded zlib issue could cause a DoS via specific
 windowBits value.
- CVE-2017-3738: Embedded OpenSSL is vulnerable to rsaz_1024_mul_avx2
 overflow bug on x86_64.
- CVE-2017-3736: Embedded OpenSSL is vulnerable to bn_sqrx8x_internal
 carry bug on x86_64 (bsc#1066242).
- CVE-2017-3735: Embedded OpenSSL is vulnerable to malformed X.509
 IPAdressFamily that could cause OOB read (bsc#1056058).
Bug fixes:
- Update to release 4.8.7 (bsc#1072322):
 *
[link moved to references]
 * [link moved to references]
 * [link moved to references]
 * [link moved to references]");

  script_tag(name:"affected", value:"'nodejs4' package(s) on SUSE Enterprise Storage 4, SUSE Linux Enterprise Module for Web Scripting 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs4", rpm:"nodejs4~4.8.7~15.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-debuginfo", rpm:"nodejs4-debuginfo~4.8.7~15.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-debugsource", rpm:"nodejs4-debugsource~4.8.7~15.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-devel", rpm:"nodejs4-devel~4.8.7~15.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs4-docs", rpm:"nodejs4-docs~4.8.7~15.8.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm4", rpm:"npm4~4.8.7~15.8.1", rls:"SLES12.0"))) {
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
