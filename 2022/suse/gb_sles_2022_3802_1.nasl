# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3802.1");
  script_cve_id("CVE-2018-20846", "CVE-2018-21010", "CVE-2020-27814", "CVE-2020-27824", "CVE-2020-27841", "CVE-2020-27842", "CVE-2020-27843", "CVE-2020-27845");
  script_tag(name:"creation_date", value:"2022-10-28 04:36:32 +0000 (Fri, 28 Oct 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3802-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3802-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223802-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2' package(s) announced via the SUSE-SU-2022:3802-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openjpeg2 fixes the following issues:

 - CVE-2018-20846: Fixed OOB read in pi_next_lrcp, pi_next_rlcp,
 pi_next_rpcl, pi_next_pcrl, pi_next_rpcl, and pi_next_cprl in
 openmj2/pi.c (bsc#1140205).
 - CVE-2018-21010: Fixed heap buffer overflow in color_apply_icc_profile
 in bin/common/color.c (bsc#1149789).
 - CVE-2020-27814: Fixed heap buffer overflow in lib/openjp2/mqc.c
 (bsc#1179594),
 - CVE-2020-27824: Fixed OOB read in opj_dwt_calc_explicit_stepsizes()
 (bsc#1179821).
 - CVE-2020-27841: Fixed buffer over-read in lib/openjp2/pi.c
 (bsc#1180042).
 - CVE-2020-27842: Fixed null pointer dereference in opj_tgt_reset
 function in lib/openjp2/tgt.c (bsc#1180043).
 - CVE-2020-27843: Fixed OOB read in opj_t2_encode_packet function in
 openjp2/t2.c (bsc#1180044).
 - CVE-2020-27845: Fixed heap-based buffer over-read in functions
 opj_pi_next_rlcp, opj_pi_next_rpcl and opj_pi_next_lrcp in
 openjp2/pi.c (bsc#1180046).");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit", rpm:"libopenjp2-7-32bit~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit-debuginfo", rpm:"libopenjp2-7-32bit-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.8.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit", rpm:"libopenjp2-7-32bit~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-32bit-debuginfo", rpm:"libopenjp2-7-32bit-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.8.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.3.0~150000.3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2", rpm:"openjpeg2~2.3.0~150000.3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.3.0~150000.3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.3.0~150000.3.8.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-devel", rpm:"openjpeg2-devel~2.3.0~150000.3.8.1", rls:"SLES15.0SP2"))) {
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
