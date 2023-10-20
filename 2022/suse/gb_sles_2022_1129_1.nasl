# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1129.1");
  script_cve_id("CVE-2016-1924", "CVE-2016-3183", "CVE-2016-4797", "CVE-2018-14423", "CVE-2018-16375", "CVE-2018-16376", "CVE-2018-20845", "CVE-2018-20846", "CVE-2020-15389", "CVE-2020-27823", "CVE-2020-8112", "CVE-2021-29338", "CVE-2022-1122");
  script_tag(name:"creation_date", value:"2022-04-08 09:16:41 +0000 (Fri, 08 Apr 2022)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-02 12:15:00 +0000 (Fri, 02 Apr 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1129-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221129-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjpeg2' package(s) announced via the SUSE-SU-2022:1129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openjpeg2 fixes the following issues:

CVE-2016-1924: Fixed heap buffer overflow (bsc#980504).

CVE-2016-3183: Fixed out-of-bounds read in sycc422_to_rgb function
 (bsc#971617).

CVE-2016-4797: Fixed heap buffer overflow (bsc#980504).

CVE-2018-14423: Fixed division-by-zero vulnerabilities in the functions
 pi_next_pcrl, pi_next_cprl,and pi_next_rpcl in lib/openjp3d/pi.c
 (bsc#1102016).

CVE-2018-16375: Fixed missing checks for header_info.height and
 header_info.width in the function pnmtoimage in bin/jpwl/convert.c
 (bsc#1106882).

CVE-2018-16376: Fixed heap-based buffer overflow function
 t2_encode_packet in lib/openmj2/t2.c (bsc#1106881).

CVE-2018-20845: Fixed division-by-zero in the functions pi_next_pcrl,
 pi_next_cprl, and pi_next_rpcl in openmj2/pi.c (bsc#1140130).

CVE-2018-20846: Fixed out-of-bounds accesses in pi_next_lrcp,
 pi_next_rlcp, pi_next_rpcl, pi_next_pcrl, pi_next_rpcl, and pi_next_cprl
 in openmj2/pi.c (bsc#1140205).

CVE-2020-8112: Fixed heap-based buffer overflow in
 opj_t1_clbl_decode_processor in openjp2/t1.c (bsc#1162090).

CVE-2020-15389: Fixed use-after-free if t a mix of valid and invalid
 files in a directory operated on by the decompressor (bsc#1173578).

CVE-2020-27823: Fixed heap buffer over-write in
 opj_tcd_dc_level_shift_encode() (bsc#1180457).

CVE-2021-29338: Fixed integer overflow that allows remote attackers to
 crash the application (bsc#1184774).

CVE-2022-1122: Fixed segmentation fault in opj2_decompress due to
 uninitialized pointer (bsc#1197738).");

  script_tag(name:"affected", value:"'openjpeg2' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.1.0~4.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.1.0~4.15.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.1.0~4.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.1.0~4.15.1", rls:"SLES12.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.1.0~4.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.1.0~4.15.1", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7", rpm:"libopenjp2-7~2.1.0~4.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenjp2-7-debuginfo", rpm:"libopenjp2-7-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debuginfo", rpm:"openjpeg2-debuginfo~2.1.0~4.15.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openjpeg2-debugsource", rpm:"openjpeg2-debugsource~2.1.0~4.15.1", rls:"SLES12.0SP5"))) {
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
