# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.1663.1");
  script_cve_id("CVE-2014-8962", "CVE-2014-9028");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2023-06-20T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:22 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:1663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:1663-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20141663-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flac' package(s) announced via the SUSE-SU-2014:1663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"flac was updated to fix two security issues.

These security issues were fixed:
- Stack overflow may result in arbitrary code execution (CVE-2014-8962).
- Heap overflow via specially crafted .flac files (CVE-2014-9028).");

  script_tag(name:"affected", value:"'flac' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12.");

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

  if(!isnull(res = isrpmvuln(pkg:"flac-debuginfo", rpm:"flac-debuginfo~1.3.0~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flac-debugsource", rpm:"flac-debugsource~1.3.0~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6", rpm:"libFLAC++6~1.3.0~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC++6-debuginfo", rpm:"libFLAC++6-debuginfo~1.3.0~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8", rpm:"libFLAC8~1.3.0~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-32bit", rpm:"libFLAC8-32bit~1.3.0~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-debuginfo", rpm:"libFLAC8-debuginfo~1.3.0~6.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libFLAC8-debuginfo-32bit", rpm:"libFLAC8-debuginfo-32bit~1.3.0~6.1", rls:"SLES12.0"))) {
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
