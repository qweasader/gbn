# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2989.2");
  script_cve_id("CVE-2022-2625");
  script_tag(name:"creation_date", value:"2022-09-27 04:47:45 +0000 (Tue, 27 Sep 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 19:09:00 +0000 (Fri, 19 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2989-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2989-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222989-2/");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/14.4/");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/p-2470/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql14' package(s) announced via the SUSE-SU-2022:2989-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql14 fixes the following issues:

Upgrade to version 14.5:

CVE-2022-2625: Fixed an issue where extension scripts would replace
 objects not belonging to that extension (bsc#1202368).

Upgrade to version 14.4 (bsc#1200437)

Release notes: [link moved to references]

Release announcement: [link moved to references]

Prevent possible corruption of indexes created or rebuilt with the
 CONCURRENTLY option (bsc#1200437)

Pin to llvm13 until the next patchlevel update (bsc#1198166)");

  script_tag(name:"affected", value:"'postgresql14' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit", rpm:"postgresql14-llvmjit~14.5~150200.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-llvmjit-debuginfo", rpm:"postgresql14-llvmjit-debuginfo~14.5~150200.5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"postgresql14-test", rpm:"postgresql14-test~14.5~150200.5.17.1", rls:"SLES15.0SP4"))) {
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
