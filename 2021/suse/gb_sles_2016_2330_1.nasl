# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2330.1");
  script_cve_id("CVE-2016-5419", "CVE-2016-5420", "CVE-2016-5421", "CVE-2016-7141");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-08 17:43:00 +0000 (Fri, 08 May 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2330-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162330-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2016:2330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for curl fixes the following issues:
Security issues fixed:
- CVE-2016-5419: TLS session resumption client cert bypass (bsc#991389)
- CVE-2016-5420: Re-using connections with wrong client cert (bsc#991390)
- CVE-2016-5421: use of connection struct after free (bsc#991391)
- CVE-2016-7141: Fixed incorrect reuse of client certificates with NSS
 (bsc#997420)
Also the following bug was fixed:
- fixing a performance issue (bsc#991746)");

  script_tag(name:"affected", value:"'curl' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.37.0~28.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debuginfo", rpm:"curl-debuginfo~7.37.0~28.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-debugsource", rpm:"curl-debugsource~7.37.0~28.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.37.0~28.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.37.0~28.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-debuginfo-32bit", rpm:"libcurl4-debuginfo-32bit~7.37.0~28.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-debuginfo", rpm:"libcurl4-debuginfo~7.37.0~28.1", rls:"SLES12.0SP1"))) {
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
