# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833341");
  script_version("2024-05-16T05:05:35+0000");
  script_cve_id("CVE-2023-40474", "CVE-2023-40476");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-05-16 05:05:35 +0000 (Thu, 16 May 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 08:06:20 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for gstreamer (SUSE-SU-2023:4594-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4594-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/J7BVPB4XTYA5B2FDLVM3XSUVXDLM6YEK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer'
  package(s) announced via the SUSE-SU-2023:4594-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-bad fixes the following issues:

  * CVE-2023-40474: Fixed integer overflow causing out of bounds writes when
      handling invalid uncompressed video (bsc#1215796).

  * CVE-2023-40476: Fixed possible overflow using max_sub_layers_minus1
      (bsc#1215793).

  ##");

  script_tag(name:"affected", value:"'gstreamer' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-debuginfo", rpm:"libgstcodecparsers-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0", rpm:"libgstinsertbin-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debugsource", rpm:"gstreamer-plugins-bad-debugsource~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-debuginfo", rpm:"libgstmpegts-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint", rpm:"gstreamer-plugins-bad-chromaprint~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0", rpm:"libgstphotography-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstInsertBin-1_0", rpm:"typelib-1_0-GstInsertBin-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-debuginfo", rpm:"libgstadaptivedemux-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-debuginfo", rpm:"libgsturidownloader-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0", rpm:"libgstbasecamerabinsrc-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0", rpm:"libgstbadaudio-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad", rpm:"gstreamer-plugins-bad~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0", rpm:"libgstwayland-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0", rpm:"libgstplayer-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0", rpm:"libgstisoff-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-doc", rpm:"gstreamer-plugins-bad-doc~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-devel", rpm:"gstreamer-plugins-bad-devel~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0", rpm:"libgstsctp-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-debuginfo", rpm:"libgstwayland-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0", rpm:"libgstcodecparsers-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0", rpm:"libgstwebrtc-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-debuginfo", rpm:"libgstplayer-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-debuginfo", rpm:"libgstphotography-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debuginfo", rpm:"gstreamer-plugins-bad-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstMpegts-1_0", rpm:"typelib-1_0-GstMpegts-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPlayer-1_0", rpm:"typelib-1_0-GstPlayer-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-debuginfo", rpm:"libgstsctp-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-debuginfo", rpm:"libgstwebrtc-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0", rpm:"libgstmpegts-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-debuginfo", rpm:"libgstinsertbin-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-debuginfo", rpm:"libgstisoff-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0", rpm:"libgsturidownloader-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-debuginfo", rpm:"libgstbadaudio-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0", rpm:"libgstadaptivedemux-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-debuginfo", rpm:"gstreamer-plugins-bad-chromaprint-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstWebRTC-1_0", rpm:"typelib-1_0-GstWebRTC-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-32bit-debuginfo", rpm:"libgstinsertbin-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-32bit", rpm:"libgstmpegts-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-32bit", rpm:"libgstplayer-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-32bit", rpm:"libgstbadaudio-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-32bit", rpm:"libgstwayland-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-32bit-debuginfo", rpm:"libgstcodecparsers-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-32bit", rpm:"libgsturidownloader-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-32bit-debuginfo", rpm:"libgsturidownloader-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-32bit-debuginfo", rpm:"libgstwayland-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-32bit", rpm:"libgstwebrtc-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-32bit-debuginfo", rpm:"libgstplayer-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-32bit-debuginfo", rpm:"libgstmpegts-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-32bit-debuginfo", rpm:"gstreamer-plugins-bad-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-32bit", rpm:"libgstcodecparsers-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-32bit", rpm:"libgstadaptivedemux-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-32bit-debuginfo", rpm:"libgstphotography-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-32bit", rpm:"libgstinsertbin-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-32bit", rpm:"libgstbasecamerabinsrc-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-32bit-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-32bit-debuginfo", rpm:"libgstsctp-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-32bit", rpm:"libgstisoff-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-32bit-debuginfo", rpm:"gstreamer-plugins-bad-chromaprint-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-32bit", rpm:"gstreamer-plugins-bad-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-32bit", rpm:"gstreamer-plugins-bad-chromaprint-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-32bit", rpm:"libgstphotography-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-32bit-debuginfo", rpm:"libgstisoff-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-32bit-debuginfo", rpm:"libgstbadaudio-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-32bit", rpm:"libgstsctp-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-32bit-debuginfo", rpm:"libgstwebrtc-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-32bit-debuginfo", rpm:"libgstadaptivedemux-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-lang", rpm:"gstreamer-plugins-bad-lang~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-64bit", rpm:"libgstbadaudio-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-64bit", rpm:"libgstbasecamerabinsrc-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-64bit-debuginfo", rpm:"libgstbadaudio-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-64bit", rpm:"libgstmpegts-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-64bit-debuginfo", rpm:"libgsturidownloader-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-64bit-debuginfo", rpm:"libgstplayer-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-64bit-debuginfo", rpm:"gstreamer-plugins-bad-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-64bit", rpm:"libgstwayland-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-64bit", rpm:"libgstsctp-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-64bit-debuginfo", rpm:"libgstadaptivedemux-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-64bit", rpm:"gstreamer-plugins-bad-chromaprint-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-64bit", rpm:"libgsturidownloader-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-64bit-debuginfo", rpm:"libgstmpegts-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-64bit", rpm:"libgstwebrtc-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-64bit-debuginfo", rpm:"gstreamer-plugins-bad-chromaprint-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-64bit", rpm:"gstreamer-plugins-bad-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-64bit-debuginfo", rpm:"libgstwayland-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-64bit-debuginfo", rpm:"libgstinsertbin-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-64bit", rpm:"libgstadaptivedemux-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-64bit-debuginfo", rpm:"libgstwebrtc-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-64bit", rpm:"libgstphotography-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-64bit", rpm:"libgstisoff-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-64bit-debuginfo", rpm:"libgstisoff-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-64bit-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-64bit-debuginfo", rpm:"libgstcodecparsers-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-64bit", rpm:"libgstinsertbin-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-64bit-debuginfo", rpm:"libgstsctp-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-64bit-debuginfo", rpm:"libgstphotography-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-64bit", rpm:"libgstplayer-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-64bit", rpm:"libgstcodecparsers-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-debuginfo", rpm:"libgstcodecparsers-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0", rpm:"libgstinsertbin-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debugsource", rpm:"gstreamer-plugins-bad-debugsource~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-debuginfo", rpm:"libgstmpegts-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint", rpm:"gstreamer-plugins-bad-chromaprint~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0", rpm:"libgstphotography-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstInsertBin-1_0", rpm:"typelib-1_0-GstInsertBin-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-debuginfo", rpm:"libgstadaptivedemux-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-debuginfo", rpm:"libgsturidownloader-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0", rpm:"libgstbasecamerabinsrc-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0", rpm:"libgstbadaudio-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad", rpm:"gstreamer-plugins-bad~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0", rpm:"libgstwayland-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0", rpm:"libgstplayer-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0", rpm:"libgstisoff-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-doc", rpm:"gstreamer-plugins-bad-doc~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-devel", rpm:"gstreamer-plugins-bad-devel~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0", rpm:"libgstsctp-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-debuginfo", rpm:"libgstwayland-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0", rpm:"libgstcodecparsers-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0", rpm:"libgstwebrtc-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-debuginfo", rpm:"libgstplayer-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-debuginfo", rpm:"libgstphotography-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-debuginfo", rpm:"gstreamer-plugins-bad-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstMpegts-1_0", rpm:"typelib-1_0-GstMpegts-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPlayer-1_0", rpm:"typelib-1_0-GstPlayer-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-debuginfo", rpm:"libgstsctp-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-debuginfo", rpm:"libgstwebrtc-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0", rpm:"libgstmpegts-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-debuginfo", rpm:"libgstinsertbin-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-debuginfo", rpm:"libgstisoff-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0", rpm:"libgsturidownloader-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-debuginfo", rpm:"libgstbadaudio-1_0-0-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0", rpm:"libgstadaptivedemux-1_0-0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-debuginfo", rpm:"gstreamer-plugins-bad-chromaprint-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstWebRTC-1_0", rpm:"typelib-1_0-GstWebRTC-1_0~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-32bit-debuginfo", rpm:"libgstinsertbin-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-32bit", rpm:"libgstmpegts-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-32bit", rpm:"libgstplayer-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-32bit", rpm:"libgstbadaudio-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-32bit", rpm:"libgstwayland-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-32bit-debuginfo", rpm:"libgstcodecparsers-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-32bit", rpm:"libgsturidownloader-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-32bit-debuginfo", rpm:"libgsturidownloader-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-32bit-debuginfo", rpm:"libgstwayland-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-32bit", rpm:"libgstwebrtc-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-32bit-debuginfo", rpm:"libgstplayer-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-32bit-debuginfo", rpm:"libgstmpegts-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-32bit-debuginfo", rpm:"gstreamer-plugins-bad-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-32bit", rpm:"libgstcodecparsers-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-32bit", rpm:"libgstadaptivedemux-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-32bit-debuginfo", rpm:"libgstphotography-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-32bit", rpm:"libgstinsertbin-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-32bit", rpm:"libgstbasecamerabinsrc-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-32bit-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-32bit-debuginfo", rpm:"libgstsctp-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-32bit", rpm:"libgstisoff-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-32bit-debuginfo", rpm:"gstreamer-plugins-bad-chromaprint-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-32bit", rpm:"gstreamer-plugins-bad-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-32bit", rpm:"gstreamer-plugins-bad-chromaprint-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-32bit", rpm:"libgstphotography-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-32bit-debuginfo", rpm:"libgstisoff-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-32bit-debuginfo", rpm:"libgstbadaudio-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-32bit", rpm:"libgstsctp-1_0-0-32bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-32bit-debuginfo", rpm:"libgstwebrtc-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-32bit-debuginfo", rpm:"libgstadaptivedemux-1_0-0-32bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-lang", rpm:"gstreamer-plugins-bad-lang~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-64bit", rpm:"libgstbadaudio-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-64bit", rpm:"libgstbasecamerabinsrc-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbadaudio-1_0-0-64bit-debuginfo", rpm:"libgstbadaudio-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-64bit", rpm:"libgstmpegts-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-64bit-debuginfo", rpm:"libgsturidownloader-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-64bit-debuginfo", rpm:"libgstplayer-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-64bit-debuginfo", rpm:"gstreamer-plugins-bad-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-64bit", rpm:"libgstwayland-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-64bit", rpm:"libgstsctp-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-64bit-debuginfo", rpm:"libgstadaptivedemux-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-64bit", rpm:"gstreamer-plugins-bad-chromaprint-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsturidownloader-1_0-0-64bit", rpm:"libgsturidownloader-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstmpegts-1_0-0-64bit-debuginfo", rpm:"libgstmpegts-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-64bit", rpm:"libgstwebrtc-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-chromaprint-64bit-debuginfo", rpm:"gstreamer-plugins-bad-chromaprint-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-bad-64bit", rpm:"gstreamer-plugins-bad-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwayland-1_0-0-64bit-debuginfo", rpm:"libgstwayland-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-64bit-debuginfo", rpm:"libgstinsertbin-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstadaptivedemux-1_0-0-64bit", rpm:"libgstadaptivedemux-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstwebrtc-1_0-0-64bit-debuginfo", rpm:"libgstwebrtc-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-64bit", rpm:"libgstphotography-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-64bit", rpm:"libgstisoff-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstisoff-1_0-0-64bit-debuginfo", rpm:"libgstisoff-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstbasecamerabinsrc-1_0-0-64bit-debuginfo", rpm:"libgstbasecamerabinsrc-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-64bit-debuginfo", rpm:"libgstcodecparsers-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstinsertbin-1_0-0-64bit", rpm:"libgstinsertbin-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsctp-1_0-0-64bit-debuginfo", rpm:"libgstsctp-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstphotography-1_0-0-64bit-debuginfo", rpm:"libgstphotography-1_0-0-64bit-debuginfo~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstplayer-1_0-0-64bit", rpm:"libgstplayer-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstcodecparsers-1_0-0-64bit", rpm:"libgstcodecparsers-1_0-0-64bit~1.16.3~150300.9.12.2", rls:"openSUSELeap15.3"))) {
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