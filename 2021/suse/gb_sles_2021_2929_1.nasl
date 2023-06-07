# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.2929.1");
  script_cve_id("CVE-2019-17539", "CVE-2019-9721", "CVE-2020-13904", "CVE-2020-20448", "CVE-2020-20451", "CVE-2020-21041", "CVE-2020-21688", "CVE-2020-21697", "CVE-2020-22015", "CVE-2020-22016", "CVE-2020-22017", "CVE-2020-22019", "CVE-2020-22020", "CVE-2020-22021", "CVE-2020-22022", "CVE-2020-22023", "CVE-2020-22025", "CVE-2020-22026", "CVE-2020-22031", "CVE-2020-22032", "CVE-2020-22033", "CVE-2020-22034", "CVE-2020-22038", "CVE-2020-22039", "CVE-2020-22043", "CVE-2020-22044", "CVE-2020-22046", "CVE-2020-22048", "CVE-2020-22049", "CVE-2020-22054", "CVE-2021-38114");
  script_tag(name:"creation_date", value:"2021-09-03 02:21:39 +0000 (Fri, 03 Sep 2021)");
  script_version("2021-09-03T02:21:39+0000");
  script_tag(name:"last_modification", value:"2021-09-03 02:21:39 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-10 13:58:00 +0000 (Thu, 10 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:2929-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:2929-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20212929-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ffmpeg' package(s) announced via the SUSE-SU-2021:2929-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ffmpeg fixes the following issues:

CVE-2019-9721: Fixed a denial of service in the subtitle decoder in
 handle_open_brace from libavcodec/htmlsubtitles.c (bsc#1129714).

CVE-2020-22046: Fixed a denial of service vulnerability due to a memory
 leak in the avpriv_float_dsp_allocl function in libavutil/float_dsp.c
 (bsc#1186849).

CVE-2020-22048: Fixed a denial of service vulnerability due to a memory
 leak in the ff_frame_pool_get function in framepool.c (bsc#1186859).

CVE-2020-22049: Fixed a denial of service vulnerability caused by a
 memory leak in the wtvfile_open_sector function in wtvdec.c
 (bsc#1186861).

CVE-2020-22054: Fixed a denial of service vulnerability due to a memory
 leak in the av_dict_set function in dict.c (bsc#1186863).

CVE-2020-13904: Fixed use-after-free via a crafted EXTINF duration in an
 m3u8 file (bsc#1172640).

CVE-2020-21041: Fixed buffer overflow vulnerability via
 apng_do_inverse_blend in libavcodec/pngenc.c (bsc#1186406).

CVE-2019-17539: Fixed NULL pointer dereference in avcodec_open2 in
 libavcodec/utils.c (bsc# 1154065).

CVE-2020-22026: Fixed buffer overflow vulnerability in config_input() at
 libavfilter/af_tremolo.c (bsc#1186583).

CVE-2020-22021: Fixed buffer overflow vulnerability in filter_edges
 function in libavfilter/vf_yadif.c (bsc#1186586).

CVE-2020-22020: Fixed buffer overflow vulnerability in build_diff_map()
 in libavfilter/vf_fieldmatch.c (bsc#1186587).

CVE-2020-22015: Fixed buffer overflow vulnerability in
 mov_write_video_tag() due to the out of bounds in libavformat/movenc.c
 (bsc#1186596).

CVE-2020-22016: Fixed a heap-based Buffer Overflow vulnerability at
 libavcodec/get_bits.h when writing .mov files (bsc#1186598).

CVE-2020-22017: Fixed a heap-based Buffer Overflow vulnerability in
 ff_fill_rectangle() in libavfilter/drawutils.c (bsc#1186600).

CVE-2020-22022: Fixed a heap-based Buffer Overflow vulnerability in
 filter_frame at libavfilter/vf_fieldorder.c (bsc#1186603).

CVE-2020-22023: Fixed a heap-based Buffer Overflow vulnerability in
 filter_frame at libavfilter/vf_bitplanenoise.c (bsc#1186604)

CVE-2020-22025: Fixed a heap-based Buffer Overflow vulnerability in
 gaussian_blur at libavfilter/vf_edgedetect.c (bsc#1186605).

CVE-2020-22031: Fixed a heap-based Buffer Overflow vulnerability at
 libavfilter/vf_w3fdif.c in filter16_complex_low() (bsc#1186613).

CVE-2020-22032: Fixed a heap-based Buffer Overflow vulnerability at
 libavfilter/vf_edgedetect.c in gaussian_blur() (bsc#1186614).

CVE-2020-22034: Fixed a heap-based Buffer Overflow vulnerability at
 libavfilter/vf_floodfill.c (bsc#1186616).

CVE-2020-20451: Fixed denial of service issue due to resource management
 errors via fftools/cmdutils.c (bsc#1186658).

CVE-2020-20448: Fixed divide by zero issue via libavcodec/ratecontrol.c
 (bsc#1186660).

CVE-2020-22038: Fixed denial of service vulnerability due to a memory
 leak in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Manager Proxy 4.0, SUSE Manager Retail Branch Server 4.0, SUSE Manager Server 4.0.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-debuginfo", rpm:"libavdevice57-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-debuginfo", rpm:"libavfilter6-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~4.34.2", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~4.34.2", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debuginfo", rpm:"ffmpeg-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ffmpeg-debugsource", rpm:"ffmpeg-debugsource~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec-devel", rpm:"libavcodec-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57", rpm:"libavcodec57~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit", rpm:"libavcodec57-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-32bit-debuginfo", rpm:"libavcodec57-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavcodec57-debuginfo", rpm:"libavcodec57-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice-devel", rpm:"libavdevice-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57", rpm:"libavdevice57~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit", rpm:"libavdevice57-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-32bit-debuginfo", rpm:"libavdevice57-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavdevice57-debuginfo", rpm:"libavdevice57-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter-devel", rpm:"libavfilter-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6", rpm:"libavfilter6~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit", rpm:"libavfilter6-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-32bit-debuginfo", rpm:"libavfilter6-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavfilter6-debuginfo", rpm:"libavfilter6-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat-devel", rpm:"libavformat-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57", rpm:"libavformat57~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit", rpm:"libavformat57-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-32bit-debuginfo", rpm:"libavformat57-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavformat57-debuginfo", rpm:"libavformat57-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample-devel", rpm:"libavresample-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3", rpm:"libavresample3~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit", rpm:"libavresample3-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-32bit-debuginfo", rpm:"libavresample3-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavresample3-debuginfo", rpm:"libavresample3-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil-devel", rpm:"libavutil-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55", rpm:"libavutil55~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit", rpm:"libavutil55-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-32bit-debuginfo", rpm:"libavutil55-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libavutil55-debuginfo", rpm:"libavutil55-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc-devel", rpm:"libpostproc-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54", rpm:"libpostproc54~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit", rpm:"libpostproc54-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-32bit-debuginfo", rpm:"libpostproc54-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpostproc54-debuginfo", rpm:"libpostproc54-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample-devel", rpm:"libswresample-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2", rpm:"libswresample2~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit", rpm:"libswresample2-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-32bit-debuginfo", rpm:"libswresample2-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswresample2-debuginfo", rpm:"libswresample2-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale-devel", rpm:"libswscale-devel~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4", rpm:"libswscale4~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit", rpm:"libswscale4-32bit~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-32bit-debuginfo", rpm:"libswscale4-32bit-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libswscale4-debuginfo", rpm:"libswscale4-debuginfo~3.4.2~4.34.2", rls:"SLES15.0SP1"))) {
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
