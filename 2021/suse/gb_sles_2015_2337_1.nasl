# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.2337.1");
  script_cve_id("CVE-2015-7519");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:09 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-29 01:29:00 +0000 (Fri, 29 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:2337-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:2337-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20152337-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem-passenger' package(s) announced via the SUSE-SU-2015:2337-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-passenger fixes the following issues:
- CVE-2015-7519: rubygem-passenger was not filtering the environment like
 apache is doing, allowing injection of environment variables (bsc#956281)");

  script_tag(name:"affected", value:"'rubygem-passenger' package(s) on SUSE Linux Enterprise Module for Containers 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-passenger", rpm:"ruby2.1-rubygem-passenger~5.0.18~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-rubygem-passenger-debuginfo", rpm:"ruby2.1-rubygem-passenger-debuginfo~5.0.18~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-passenger", rpm:"rubygem-passenger~5.0.18~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-passenger-apache2", rpm:"rubygem-passenger-apache2~5.0.18~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-passenger-apache2-debuginfo", rpm:"rubygem-passenger-apache2-debuginfo~5.0.18~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-passenger-debuginfo", rpm:"rubygem-passenger-debuginfo~5.0.18~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rubygem-passenger-debugsource", rpm:"rubygem-passenger-debugsource~5.0.18~6.1", rls:"SLES12.0"))) {
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
