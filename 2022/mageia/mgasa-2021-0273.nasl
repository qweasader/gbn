# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0273");
  script_cve_id("CVE-2020-35965");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 21:03:53 +0000 (Tue, 05 Jan 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0273)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0273");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0273.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=28276");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/dla-2537");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2021-0273 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write in decode_frame in libavcodec/exr.c because of errors
in calculations of when to perform memset zero operations (CVE-2020-35965).");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec58", rpm:"lib64avcodec58~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec58", rpm:"lib64avcodec58~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter7", rpm:"lib64avfilter7~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter7", rpm:"lib64avfilter7~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat58", rpm:"lib64avformat58~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat58", rpm:"lib64avformat58~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avresample4", rpm:"lib64avresample4~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avresample4", rpm:"lib64avresample4~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil56", rpm:"lib64avutil56~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil56", rpm:"lib64avutil56~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc55", rpm:"lib64postproc55~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc55", rpm:"lib64postproc55~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample3", rpm:"lib64swresample3~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample3", rpm:"lib64swresample3~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler5", rpm:"lib64swscaler5~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler5", rpm:"lib64swscaler5~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58", rpm:"libavcodec58~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec58", rpm:"libavcodec58~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7", rpm:"libavfilter7~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter7", rpm:"libavfilter7~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58", rpm:"libavformat58~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat58", rpm:"libavformat58~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4", rpm:"libavresample4~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample4", rpm:"libavresample4~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56", rpm:"libavutil56~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil56", rpm:"libavutil56~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55", rpm:"libpostproc55~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc55", rpm:"libpostproc55~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3", rpm:"libswresample3~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample3", rpm:"libswresample3~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler5", rpm:"libswscaler5~4.1.6~1.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler5", rpm:"libswscaler5~4.1.6~1.1.mga7.tainted", rls:"MAGEIA7"))) {
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
