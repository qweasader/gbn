# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0319");
  script_cve_id("CVE-2018-10001", "CVE-2018-12458", "CVE-2018-13300", "CVE-2018-13302", "CVE-2018-6392", "CVE-2018-6621", "CVE-2018-7557");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-18 14:32:12 +0000 (Wed, 18 Jul 2018)");

  script_name("Mageia: Security Advisory (MGASA-2018-0319)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0319");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0319.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/download.html");
  script_xref(name:"URL", value:"http://ffmpeg.org/security.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23329");
  script_xref(name:"URL", value:"https://git.ffmpeg.org/gitweb/ffmpeg.git/shortlog/n3.3.8");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the MGASA-2018-0319 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update provides ffmpeg version 3.3.8, which fixes several security
vulnerabilities and other bugs which were corrected upstream.");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg", rpm:"ffmpeg~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec57", rpm:"lib64avcodec57~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avcodec57", rpm:"lib64avcodec57~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter6", rpm:"lib64avfilter6~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avfilter6", rpm:"lib64avfilter6~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat57", rpm:"lib64avformat57~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avformat57", rpm:"lib64avformat57~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avresample3", rpm:"lib64avresample3~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avresample3", rpm:"lib64avresample3~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil55", rpm:"lib64avutil55~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64avutil55", rpm:"lib64avutil55~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-devel", rpm:"lib64ffmpeg-devel~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ffmpeg-static-devel", rpm:"lib64ffmpeg-static-devel~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc54", rpm:"lib64postproc54~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64postproc54", rpm:"lib64postproc54~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample2", rpm:"lib64swresample2~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swresample2", rpm:"lib64swresample2~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler4", rpm:"lib64swscaler4~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64swscaler4", rpm:"lib64swscaler4~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-devel", rpm:"libffmpeg-devel~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libffmpeg-static-devel", rpm:"libffmpeg-static-devel~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler4", rpm:"libswscaler4~3.3.8~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscaler4", rpm:"libswscaler4~3.3.8~1.mga6.tainted", rls:"MAGEIA6"))) {
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
