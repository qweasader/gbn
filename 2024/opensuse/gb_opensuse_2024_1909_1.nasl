# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856175");
  script_version("2024-06-07T15:38:39+0000");
  script_cve_id("CVE-2020-22021", "CVE-2023-51794");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-03 12:35:40 +0000 (Thu, 03 Jun 2021)");
  script_tag(name:"creation_date", value:"2024-06-05 01:00:42 +0000 (Wed, 05 Jun 2024)");
  script_name("openSUSE: Security Advisory for ffmpeg (SUSE-SU-2024:1909-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1909-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LLUQGQC2WLM6AM3DHFOGIDFIGUV6DJFJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the SUSE-SU-2024:1909-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg-4 fixes the following issues:

  * CVE-2020-22021: Fixed buffer overflow vulnerability in filter_edges function
      in libavfilter/vf_yadif.c (bsc#1186586).

  * CVE-2023-51794: Fixed a heap buffer overflow in libavfilter. (bsc#1223437)

  ##");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4", rpm:"ffmpeg-4~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9", rpm:"libswresample3_9~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-private-devel", rpm:"ffmpeg-4-private-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110", rpm:"libavfilter7_110~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-debuginfo", rpm:"libavutil56_70-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debuginfo", rpm:"ffmpeg-4-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-debuginfo", rpm:"libswscale5_9-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswresample-devel", rpm:"ffmpeg-4-libswresample-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70", rpm:"libavutil56_70~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debugsource", rpm:"ffmpeg-4-debugsource~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavformat-devel", rpm:"ffmpeg-4-libavformat-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavfilter-devel", rpm:"ffmpeg-4-libavfilter-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavdevice-devel", rpm:"ffmpeg-4-libavdevice-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0", rpm:"libavresample4_0~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavcodec-devel", rpm:"ffmpeg-4-libavcodec-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-debuginfo", rpm:"libpostproc55_9-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-debuginfo", rpm:"libavfilter7_110-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-debuginfo", rpm:"libavdevice58_13-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13", rpm:"libavdevice58_13~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76", rpm:"libavformat58_76~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavutil-devel", rpm:"ffmpeg-4-libavutil-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-debuginfo", rpm:"libavformat58_76-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9", rpm:"libswscale5_9~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-debuginfo", rpm:"libavresample4_0-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134", rpm:"libavcodec58_134~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavresample-devel", rpm:"ffmpeg-4-libavresample-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9", rpm:"libpostproc55_9~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-debuginfo", rpm:"libswresample3_9-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libpostproc-devel", rpm:"ffmpeg-4-libpostproc-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-debuginfo", rpm:"libavcodec58_134-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswscale-devel", rpm:"ffmpeg-4-libswscale-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-32bit", rpm:"libswresample3_9-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-32bit-debuginfo", rpm:"libavdevice58_13-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-32bit", rpm:"libswscale5_9-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-32bit-debuginfo", rpm:"libavcodec58_134-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-32bit-debuginfo", rpm:"libavresample4_0-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-32bit", rpm:"libavutil56_70-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-32bit-debuginfo", rpm:"libavformat58_76-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-32bit-debuginfo", rpm:"libavutil56_70-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-32bit", rpm:"libavfilter7_110-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-32bit-debuginfo", rpm:"libavfilter7_110-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-32bit", rpm:"libavcodec58_134-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-32bit-debuginfo", rpm:"libpostproc55_9-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-32bit", rpm:"libavresample4_0-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-32bit", rpm:"libpostproc55_9-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-32bit", rpm:"libavformat58_76-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-32bit-debuginfo", rpm:"libswscale5_9-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-32bit-debuginfo", rpm:"libswresample3_9-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-32bit", rpm:"libavdevice58_13-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-64bit-debuginfo", rpm:"libavdevice58_13-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-64bit", rpm:"libavformat58_76-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-64bit", rpm:"libavresample4_0-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-64bit", rpm:"libpostproc55_9-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-64bit", rpm:"libavcodec58_134-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-64bit-debuginfo", rpm:"libswscale5_9-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-64bit-debuginfo", rpm:"libavformat58_76-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-64bit-debuginfo", rpm:"libswresample3_9-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-64bit-debuginfo", rpm:"libavfilter7_110-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-64bit-debuginfo", rpm:"libavcodec58_134-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-64bit", rpm:"libavdevice58_13-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-64bit", rpm:"libswscale5_9-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-64bit-debuginfo", rpm:"libavutil56_70-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-64bit-debuginfo", rpm:"libpostproc55_9-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-64bit", rpm:"libavutil56_70-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-64bit-debuginfo", rpm:"libavresample4_0-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-64bit", rpm:"libswresample3_9-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-64bit", rpm:"libavfilter7_110-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4", rpm:"ffmpeg-4~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9", rpm:"libswresample3_9~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-private-devel", rpm:"ffmpeg-4-private-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110", rpm:"libavfilter7_110~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-debuginfo", rpm:"libavutil56_70-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debuginfo", rpm:"ffmpeg-4-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-debuginfo", rpm:"libswscale5_9-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswresample-devel", rpm:"ffmpeg-4-libswresample-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70", rpm:"libavutil56_70~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-debugsource", rpm:"ffmpeg-4-debugsource~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavformat-devel", rpm:"ffmpeg-4-libavformat-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavfilter-devel", rpm:"ffmpeg-4-libavfilter-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavdevice-devel", rpm:"ffmpeg-4-libavdevice-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0", rpm:"libavresample4_0~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavcodec-devel", rpm:"ffmpeg-4-libavcodec-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-debuginfo", rpm:"libpostproc55_9-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-debuginfo", rpm:"libavfilter7_110-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-debuginfo", rpm:"libavdevice58_13-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13", rpm:"libavdevice58_13~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76", rpm:"libavformat58_76~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavutil-devel", rpm:"ffmpeg-4-libavutil-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-debuginfo", rpm:"libavformat58_76-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9", rpm:"libswscale5_9~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-debuginfo", rpm:"libavresample4_0-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134", rpm:"libavcodec58_134~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libavresample-devel", rpm:"ffmpeg-4-libavresample-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9", rpm:"libpostproc55_9~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-debuginfo", rpm:"libswresample3_9-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libpostproc-devel", rpm:"ffmpeg-4-libpostproc-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-debuginfo", rpm:"libavcodec58_134-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-4-libswscale-devel", rpm:"ffmpeg-4-libswscale-devel~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-32bit", rpm:"libswresample3_9-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-32bit-debuginfo", rpm:"libavdevice58_13-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-32bit", rpm:"libswscale5_9-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-32bit-debuginfo", rpm:"libavcodec58_134-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-32bit-debuginfo", rpm:"libavresample4_0-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-32bit", rpm:"libavutil56_70-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-32bit-debuginfo", rpm:"libavformat58_76-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-32bit-debuginfo", rpm:"libavutil56_70-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-32bit", rpm:"libavfilter7_110-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-32bit-debuginfo", rpm:"libavfilter7_110-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-32bit", rpm:"libavcodec58_134-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-32bit-debuginfo", rpm:"libpostproc55_9-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-32bit", rpm:"libavresample4_0-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-32bit", rpm:"libpostproc55_9-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-32bit", rpm:"libavformat58_76-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-32bit-debuginfo", rpm:"libswscale5_9-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-32bit-debuginfo", rpm:"libswresample3_9-32bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-32bit", rpm:"libavdevice58_13-32bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-64bit-debuginfo", rpm:"libavdevice58_13-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-64bit", rpm:"libavformat58_76-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-64bit", rpm:"libavresample4_0-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-64bit", rpm:"libpostproc55_9-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-64bit", rpm:"libavcodec58_134-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-64bit-debuginfo", rpm:"libswscale5_9-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58_76-64bit-debuginfo", rpm:"libavformat58_76-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-64bit-debuginfo", rpm:"libswresample3_9-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-64bit-debuginfo", rpm:"libavfilter7_110-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58_134-64bit-debuginfo", rpm:"libavcodec58_134-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice58_13-64bit", rpm:"libavdevice58_13-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale5_9-64bit", rpm:"libswscale5_9-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-64bit-debuginfo", rpm:"libavutil56_70-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55_9-64bit-debuginfo", rpm:"libpostproc55_9-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56_70-64bit", rpm:"libavutil56_70-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4_0-64bit-debuginfo", rpm:"libavresample4_0-64bit-debuginfo~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3_9-64bit", rpm:"libswresample3_9-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7_110-64bit", rpm:"libavfilter7_110-64bit~4.4~150600.13.5.1", rls:"openSUSELeap15.6"))) {
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