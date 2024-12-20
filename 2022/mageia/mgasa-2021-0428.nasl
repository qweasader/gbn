# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0428");
  script_cve_id("CVE-2021-35940");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-28 00:55:08 +0000 (Sat, 28 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0428");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0428.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29400");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/08/23/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apr' package(s) announced via the MGASA-2021-0428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds array read in the apr_time_exp*() functions was fixed in
the Apache Portable Runtime 1.6.3 release (CVE-2017-12613). The fix for
this issue was not carried forward to the APR 1.7.x branch, and hence
version 1.7.0 regressed compared to 1.6.3 and is vulnerable to the same
issue. (CVE-2021-35940)");

  script_tag(name:"affected", value:"'apr' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"apr", rpm:"apr~1.7.0~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr-devel", rpm:"lib64apr-devel~1.7.0~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64apr1_0", rpm:"lib64apr1_0~1.7.0~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr-devel", rpm:"libapr-devel~1.7.0~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libapr1_0", rpm:"libapr1_0~1.7.0~3.2.mga8", rls:"MAGEIA8"))) {
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
