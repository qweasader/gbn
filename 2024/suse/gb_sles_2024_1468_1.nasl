# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1468.1");
  script_cve_id("CVE-2020-20894", "CVE-2020-20898", "CVE-2020-20900", "CVE-2020-20901", "CVE-2021-38090", "CVE-2021-38091", "CVE-2021-38094", "CVE-2023-49502", "CVE-2024-31578");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2024-05-09T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-05-09 05:05:43 +0000 (Thu, 09 May 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-23 15:09:44 +0000 (Thu, 23 Sep 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1468-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1468-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241468-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the SUSE-SU-2024:1468-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:

CVE-2024-31578: Fixed heap use-after-free via av_hwframe_ctx_init() when vulkan_frames init failed (bsc#1223070)
CVE-2023-49502: Fixed heap buffer overflow via the ff_bwdif_filter_intra_c function in libavfilter/bwdifdsp.c (bsc#1223235)

Adding references for already fixed issues:

CVE-2021-38091: Fixed integer overflow in function filter16_sobel in libavfilter/vf_convolution.c (bsc#1190732)
CVE-2021-38090: Fixed integer overflow in function filter16_roberts in libavfilter/vf_convolution.c (bsc#1190731)
CVE-2020-20898: Fixed integer overflow vulnerability in function filter16_prewitt in libavfilter/vf_convolution.c (bsc#1190724)
CVE-2020-20901: Fixed buffer overflow vulnerability in function filter_frame in libavfilter/vf_fieldorder.c (bsc#1190728)
CVE-2020-20900: Fixed buffer overflow vulnerability in function gaussian_blur in libavfilter/vf_edgedetect.c (bsc#1190727)
CVE-2020-20894: Fixed buffer Overflow vulnerability in function gaussian_blur in libavfilter/vf_edgedetect.c (bsc#1190721)");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP5, SUSE Package Hub 15.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~150200.11.41.1", rls:"SLES15.0SP4"))) {
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
