# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3475.1");
  script_cve_id("CVE-2020-35538");
  script_tag(name:"creation_date", value:"2022-10-03 04:37:04 +0000 (Mon, 03 Oct 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 12:41:00 +0000 (Wed, 07 Sep 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3475-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3475-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223475-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libjpeg-turbo' package(s) announced via the SUSE-SU-2022:3475-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libjpeg-turbo fixes the following issues:

CVE-2020-35538: Fixed null pointer dereference in jcopy_sample_rows()
 function (bsc#1202915).");

  script_tag(name:"affected", value:"'libjpeg-turbo' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo", rpm:"libjpeg-turbo~1.5.3~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo-debuginfo", rpm:"libjpeg-turbo-debuginfo~1.5.3~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg-turbo-debugsource", rpm:"libjpeg-turbo-debugsource~1.5.3~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-32bit", rpm:"libjpeg62-32bit~62.2.0~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62", rpm:"libjpeg62~62.2.0~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-debuginfo-32bit", rpm:"libjpeg62-debuginfo-32bit~62.2.0~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-debuginfo", rpm:"libjpeg62-debuginfo~62.2.0~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-turbo", rpm:"libjpeg62-turbo~1.5.3~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg62-turbo-debugsource", rpm:"libjpeg62-turbo-debugsource~1.5.3~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-32bit", rpm:"libjpeg8-32bit~8.1.2~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8", rpm:"libjpeg8~8.1.2~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-debuginfo-32bit", rpm:"libjpeg8-debuginfo-32bit~8.1.2~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjpeg8-debuginfo", rpm:"libjpeg8-debuginfo~8.1.2~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0", rpm:"libturbojpeg0~8.1.2~31.28.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libturbojpeg0-debuginfo", rpm:"libturbojpeg0-debuginfo~8.1.2~31.28.1", rls:"SLES12.0SP5"))) {
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
