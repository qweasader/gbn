# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1884.1");
  script_cve_id("CVE-2018-10194");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:43 +0000 (Wed, 09 Jun 2021)");
  script_version("2023-06-20T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:23 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-24 16:21:00 +0000 (Wed, 24 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1884-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1884-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181884-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the SUSE-SU-2018:1884-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript fixes the following issues:
- CVE-2018-10194: The set_text_distance function did not prevent overflows
 in text-positioning calculation, which allowed remote attackers to cause
 a denial
 of service (application crash) or possibly have unspecified other impact
 via a crafted PDF document (bsc#1090099).");

  script_tag(name:"affected", value:"'ghostscript' package(s) on SUSE Linux Enterprise Module for Basesystem 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.23~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~9.23~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~9.23~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.23~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~9.23~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11-debuginfo", rpm:"ghostscript-x11-debuginfo~9.23~3.3.1", rls:"SLES15.0"))) {
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
