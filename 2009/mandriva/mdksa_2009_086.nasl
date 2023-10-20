# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63719");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-06 20:58:11 +0200 (Mon, 06 Apr 2009)");
  script_cve_id("CVE-2009-0398");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Mandrake Security Advisory MDVSA-2009:086 (gstreamer-plugins)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_3\.0");
  script_tag(name:"insight", value:"An array indexing error in the GStreamer's QuickTime media file
format decoding plug-in enables attackers to crash the application
and potentially execute arbitrary code by using a crafted media file
(CVE-2009-0398).

This update provides fix for that security issue.

Affected: Corporate 3.0");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:086");
  script_tag(name:"summary", value:"The remote host is missing an update to gstreamer-plugins
announced via advisory MDVSA-2009:086.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gstreamer-a52dec", rpm:"gstreamer-a52dec~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-aalib", rpm:"gstreamer-aalib~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-arts", rpm:"gstreamer-arts~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-artsd", rpm:"gstreamer-artsd~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-audio-effects", rpm:"gstreamer-audio-effects~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-audiofile", rpm:"gstreamer-audiofile~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-audio-formats", rpm:"gstreamer-audio-formats~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-avi", rpm:"gstreamer-avi~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-cdparanoia", rpm:"gstreamer-cdparanoia~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-cdplayer", rpm:"gstreamer-cdplayer~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-colorspace", rpm:"gstreamer-colorspace~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-dv", rpm:"gstreamer-dv~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-dxr3", rpm:"gstreamer-dxr3~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-esound", rpm:"gstreamer-esound~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-festival", rpm:"gstreamer-festival~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-ffmpeg", rpm:"gstreamer-ffmpeg~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-flac", rpm:"gstreamer-flac~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-flx", rpm:"gstreamer-flx~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-GConf", rpm:"gstreamer-GConf~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-gnomevfs", rpm:"gstreamer-gnomevfs~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-gsm", rpm:"gstreamer-gsm~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-httpsrc", rpm:"gstreamer-httpsrc~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-jack", rpm:"gstreamer-jack~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-jpeg", rpm:"gstreamer-jpeg~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-jpegmmx", rpm:"gstreamer-jpegmmx~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-ladspa", rpm:"gstreamer-ladspa~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-libdvdnav", rpm:"gstreamer-libdvdnav~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-libdvdread", rpm:"gstreamer-libdvdread~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-libpng", rpm:"gstreamer-libpng~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-mad", rpm:"gstreamer-mad~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-mikmod", rpm:"gstreamer-mikmod~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-mpeg", rpm:"gstreamer-mpeg~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-oss", rpm:"gstreamer-oss~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-plugins", rpm:"gstreamer-plugins~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-plugins-devel", rpm:"gstreamer-plugins-devel~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-qcam", rpm:"gstreamer-qcam~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-quicktime", rpm:"gstreamer-quicktime~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-raw1394", rpm:"gstreamer-raw1394~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-SDL", rpm:"gstreamer-SDL~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-sid", rpm:"gstreamer-sid~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-snapshot", rpm:"gstreamer-snapshot~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-swfdec", rpm:"gstreamer-swfdec~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-udp", rpm:"gstreamer-udp~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-v4l", rpm:"gstreamer-v4l~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-vcd", rpm:"gstreamer-vcd~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-video-effects", rpm:"gstreamer-video-effects~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-videosink", rpm:"gstreamer-videosink~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-videotest", rpm:"gstreamer-videotest~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-visualisation", rpm:"gstreamer-visualisation~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-vorbis", rpm:"gstreamer-vorbis~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-xvideosink", rpm:"gstreamer-xvideosink~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer-yuv4mjpeg", rpm:"gstreamer-yuv4mjpeg~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstgconf0.6", rpm:"libgstgconf0.6~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgstplay0.6", rpm:"libgstplay0.6~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstgconf0.6", rpm:"lib64gstgconf0.6~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gstplay0.6", rpm:"lib64gstplay0.6~0.6.4~4.2mdk", rls:"MNDK_3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
