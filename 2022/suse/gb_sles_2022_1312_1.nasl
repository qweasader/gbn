# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1312.1");
  script_cve_id("CVE-2020-14409", "CVE-2020-14410", "CVE-2021-33657");
  script_tag(name:"creation_date", value:"2022-04-25 04:21:21 +0000 (Mon, 25 Apr 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-12 17:49:00 +0000 (Tue, 12 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1312-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1312-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221312-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'SDL' package(s) announced via the SUSE-SU-2022:1312-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for SDL fixes the following issues:

CVE-2020-14409: Fixed an integer overflow (and resultant SDL_memcpy heap
 corruption) in SDL_BlitCopy in video/SDL_blit_copy.c. (bsc#1181202)

CVE-2020-14410: Fixed a heap-based buffer over-read in
 Blit_3or4_to_3or4__inversed_rgb in video/SDL_blit_N.c. (bsc#1181201)

CVE-2021-33657: Fixed a Heap overflow problem in video/SDL_pixels.c.
 (bsc#1198001)");

  script_tag(name:"affected", value:"'SDL' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"SDL-debugsource", rpm:"SDL-debugsource~1.2.15~15.17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0", rpm:"libSDL-1_2-0~1.2.15~15.17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit", rpm:"libSDL-1_2-0-32bit~1.2.15~15.17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo", rpm:"libSDL-1_2-0-debuginfo~1.2.15~15.17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo-32bit", rpm:"libSDL-1_2-0-debuginfo-32bit~1.2.15~15.17.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"SDL-debugsource", rpm:"SDL-debugsource~1.2.15~15.17.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0", rpm:"libSDL-1_2-0~1.2.15~15.17.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit", rpm:"libSDL-1_2-0-32bit~1.2.15~15.17.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo", rpm:"libSDL-1_2-0-debuginfo~1.2.15~15.17.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo-32bit", rpm:"libSDL-1_2-0-debuginfo-32bit~1.2.15~15.17.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"SDL-debugsource", rpm:"SDL-debugsource~1.2.15~15.17.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0", rpm:"libSDL-1_2-0~1.2.15~15.17.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit", rpm:"libSDL-1_2-0-32bit~1.2.15~15.17.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo", rpm:"libSDL-1_2-0-debuginfo~1.2.15~15.17.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo-32bit", rpm:"libSDL-1_2-0-debuginfo-32bit~1.2.15~15.17.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"SDL-debugsource", rpm:"SDL-debugsource~1.2.15~15.17.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0", rpm:"libSDL-1_2-0~1.2.15~15.17.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-32bit", rpm:"libSDL-1_2-0-32bit~1.2.15~15.17.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo", rpm:"libSDL-1_2-0-debuginfo~1.2.15~15.17.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libSDL-1_2-0-debuginfo-32bit", rpm:"libSDL-1_2-0-debuginfo-32bit~1.2.15~15.17.1", rls:"SLES12.0SP5"))) {
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
