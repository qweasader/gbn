# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.1470.1");
  script_cve_id("CVE-2023-49502", "CVE-2023-51793", "CVE-2024-31578");
  script_tag(name:"creation_date", value:"2024-05-07 13:39:54 +0000 (Tue, 07 May 2024)");
  script_version("2024-05-09T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-05-09 05:05:43 +0000 (Thu, 09 May 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:1470-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1470-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20241470-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg-4' package(s) announced via the SUSE-SU-2024:1470-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 fixes the following issues:

CVE-2024-31578: Fixed heap use-after-free via av_hwframe_ctx_init() when vulkan_frames init failed (bsc#1223070)
CVE-2023-49502: Fixed heap buffer overflow via the ff_bwdif_filter_intra_c function in libavfilter/bwdifdsp.c (bsc#1223235)
CVE-2023-51793: Fixed heap buffer overflow in the image_copy_plane function in libavutil/imgutils.c (bsc#1223272)");

  script_tag(name:"affected", value:"'ffmpeg-4' package(s) on SUSE Linux Enterprise Desktop 15-SP4, SUSE Linux Enterprise High Performance Computing 15-SP4, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP5, SUSE Package Hub 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debuginfo", rpm:"ffmpeg-4-debuginfo~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debugsource", rpm:"ffmpeg-4-debugsource~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134", rpm:"libavcodec58_134~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-debuginfo", rpm:"libavcodec58_134-debuginfo~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76", rpm:"libavformat58_76~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-debuginfo", rpm:"libavformat58_76-debuginfo~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70", rpm:"libavutil56_70~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-debuginfo", rpm:"libavutil56_70-debuginfo~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9", rpm:"libpostproc55_9~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-debuginfo", rpm:"libpostproc55_9-debuginfo~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9", rpm:"libswresample3_9~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-debuginfo", rpm:"libswresample3_9-debuginfo~4.4~150400.3.24.1", rls:"SLES15.0SP4"))) {
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
