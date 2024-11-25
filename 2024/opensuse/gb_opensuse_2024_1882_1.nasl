# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856190");
  script_version("2024-06-07T15:38:39+0000");
  script_cve_id("CVE-2024-4453");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-06-07 15:38:39 +0000 (Fri, 07 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-05 01:01:01 +0000 (Wed, 05 Jun 2024)");
  script_name("openSUSE: Security Advisory for gstreamer (SUSE-SU-2024:1882-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1882-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Z7S2WLU7BJDINGHGXH5VN3UCIDE4XXQM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer'
  package(s) announced via the SUSE-SU-2024:1882-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-base fixes the following issues:

  * CVE-2024-4453: Fixed lack of proper validation of user-supplied data when
      parsing EXIF metadata (bsc#1224806)

  ##");

  script_tag(name:"affected", value:"'gstreamer' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-debuginfo", rpm:"libgstrtp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGLX11-1_0", rpm:"typelib-1_0-GstGLX11-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-debuginfo", rpm:"libgsttag-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0", rpm:"libgstallocators-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-debuginfo", rpm:"libgstriff-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-debuginfo", rpm:"libgstrtsp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-debuginfo", rpm:"libgstpbutils-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0", rpm:"libgstaudio-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAllocators-1_0", rpm:"typelib-1_0-GstAllocators-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0", rpm:"libgstvideo-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstTag-1_0", rpm:"typelib-1_0-GstTag-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtp-1_0", rpm:"typelib-1_0-GstRtp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtsp-1_0", rpm:"typelib-1_0-GstRtsp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0", rpm:"libgstsdp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-debuginfo", rpm:"libgstgl-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-debuginfo", rpm:"libgstsdp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-debuginfo", rpm:"libgstvideo-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0", rpm:"libgstfft-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0", rpm:"libgstpbutils-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel", rpm:"gstreamer-plugins-base-devel~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0", rpm:"libgstrtsp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPbutils-1_0", rpm:"typelib-1_0-GstPbutils-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0", rpm:"libgstapp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0", rpm:"libgstriff-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-debuginfo", rpm:"libgstfft-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0", rpm:"libgsttag-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debuginfo", rpm:"gstreamer-plugins-base-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0", rpm:"libgstrtp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAudio-1_0", rpm:"typelib-1_0-GstAudio-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstSdp-1_0", rpm:"typelib-1_0-GstSdp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-debuginfo", rpm:"libgstapp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstVideo-1_0", rpm:"typelib-1_0-GstVideo-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0", rpm:"libgstgl-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debugsource", rpm:"gstreamer-plugins-base-debugsource~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGLWayland-1_0", rpm:"typelib-1_0-GstGLWayland-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGL-1_0", rpm:"typelib-1_0-GstGL-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-debuginfo", rpm:"libgstallocators-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstApp-1_0", rpm:"typelib-1_0-GstApp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGLEGL-1_0", rpm:"typelib-1_0-GstGLEGL-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-debuginfo", rpm:"libgstaudio-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-32bit", rpm:"libgstsdp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-32bit-debuginfo", rpm:"libgstpbutils-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-32bit-debuginfo", rpm:"libgstsdp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-32bit", rpm:"libgstpbutils-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-32bit-debuginfo", rpm:"libgstriff-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-32bit", rpm:"libgstaudio-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-32bit-debuginfo", rpm:"libgstapp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-32bit", rpm:"libgstriff-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-32bit", rpm:"gstreamer-plugins-base-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-32bit-debuginfo", rpm:"libgstrtp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-32bit", rpm:"libgstfft-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-32bit", rpm:"libgstapp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-32bit-debuginfo", rpm:"libgstaudio-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-32bit-debuginfo", rpm:"libgstgl-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-32bit-debuginfo", rpm:"libgstrtsp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-32bit-debuginfo", rpm:"libgstallocators-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-32bit", rpm:"libgsttag-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-32bit", rpm:"libgstrtp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-32bit", rpm:"libgstallocators-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-32bit-debuginfo", rpm:"libgstvideo-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-32bit", rpm:"libgstvideo-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel-32bit", rpm:"gstreamer-plugins-base-devel-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-32bit-debuginfo", rpm:"libgsttag-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-32bit", rpm:"libgstgl-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-32bit-debuginfo", rpm:"libgstfft-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-32bit-debuginfo", rpm:"gstreamer-plugins-base-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-32bit", rpm:"libgstrtsp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-lang", rpm:"gstreamer-plugins-base-lang~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-64bit", rpm:"libgstrtsp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-64bit-debuginfo", rpm:"libgstaudio-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-64bit", rpm:"libgstsdp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-64bit", rpm:"libgstgl-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-64bit", rpm:"libgstaudio-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-64bit-debuginfo", rpm:"libgstrtsp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-64bit-debuginfo", rpm:"libgstpbutils-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-64bit", rpm:"libgstfft-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-64bit", rpm:"libgstallocators-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-64bit-debuginfo", rpm:"gstreamer-plugins-base-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-64bit-debuginfo", rpm:"libgstrtp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-64bit", rpm:"libgstvideo-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-64bit", rpm:"libgstriff-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-64bit-debuginfo", rpm:"libgstfft-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-64bit", rpm:"libgstrtp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel-64bit", rpm:"gstreamer-plugins-base-devel-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-64bit", rpm:"libgstapp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-64bit-debuginfo", rpm:"libgstallocators-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-64bit-debuginfo", rpm:"libgstvideo-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-64bit", rpm:"gstreamer-plugins-base-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-64bit-debuginfo", rpm:"libgstsdp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-64bit", rpm:"libgstpbutils-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-64bit-debuginfo", rpm:"libgstgl-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-64bit-debuginfo", rpm:"libgstriff-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-64bit-debuginfo", rpm:"libgstapp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-64bit-debuginfo", rpm:"libgsttag-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-64bit", rpm:"libgsttag-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-debuginfo", rpm:"libgstrtp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGLX11-1_0", rpm:"typelib-1_0-GstGLX11-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-debuginfo", rpm:"libgsttag-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0", rpm:"libgstallocators-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-debuginfo", rpm:"libgstriff-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-debuginfo", rpm:"libgstrtsp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-debuginfo", rpm:"libgstpbutils-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0", rpm:"libgstaudio-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAllocators-1_0", rpm:"typelib-1_0-GstAllocators-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0", rpm:"libgstvideo-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstTag-1_0", rpm:"typelib-1_0-GstTag-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtp-1_0", rpm:"typelib-1_0-GstRtp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtsp-1_0", rpm:"typelib-1_0-GstRtsp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0", rpm:"libgstsdp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-debuginfo", rpm:"libgstgl-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-debuginfo", rpm:"libgstsdp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-debuginfo", rpm:"libgstvideo-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0", rpm:"libgstfft-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0", rpm:"libgstpbutils-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel", rpm:"gstreamer-plugins-base-devel~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0", rpm:"libgstrtsp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPbutils-1_0", rpm:"typelib-1_0-GstPbutils-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0", rpm:"libgstapp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0", rpm:"libgstriff-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-debuginfo", rpm:"libgstfft-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0", rpm:"libgsttag-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debuginfo", rpm:"gstreamer-plugins-base-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0", rpm:"libgstrtp-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAudio-1_0", rpm:"typelib-1_0-GstAudio-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstSdp-1_0", rpm:"typelib-1_0-GstSdp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-debuginfo", rpm:"libgstapp-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstVideo-1_0", rpm:"typelib-1_0-GstVideo-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0", rpm:"libgstgl-1_0-0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debugsource", rpm:"gstreamer-plugins-base-debugsource~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGLWayland-1_0", rpm:"typelib-1_0-GstGLWayland-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGL-1_0", rpm:"typelib-1_0-GstGL-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-debuginfo", rpm:"libgstallocators-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstApp-1_0", rpm:"typelib-1_0-GstApp-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGLEGL-1_0", rpm:"typelib-1_0-GstGLEGL-1_0~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-debuginfo", rpm:"libgstaudio-1_0-0-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-32bit", rpm:"libgstsdp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-32bit-debuginfo", rpm:"libgstpbutils-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-32bit-debuginfo", rpm:"libgstsdp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-32bit", rpm:"libgstpbutils-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-32bit-debuginfo", rpm:"libgstriff-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-32bit", rpm:"libgstaudio-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-32bit-debuginfo", rpm:"libgstapp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-32bit", rpm:"libgstriff-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-32bit", rpm:"gstreamer-plugins-base-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-32bit-debuginfo", rpm:"libgstrtp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-32bit", rpm:"libgstfft-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-32bit", rpm:"libgstapp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-32bit-debuginfo", rpm:"libgstaudio-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-32bit-debuginfo", rpm:"libgstgl-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-32bit-debuginfo", rpm:"libgstrtsp-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-32bit-debuginfo", rpm:"libgstallocators-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-32bit", rpm:"libgsttag-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-32bit", rpm:"libgstrtp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-32bit", rpm:"libgstallocators-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-32bit-debuginfo", rpm:"libgstvideo-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-32bit", rpm:"libgstvideo-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel-32bit", rpm:"gstreamer-plugins-base-devel-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-32bit-debuginfo", rpm:"libgsttag-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-32bit", rpm:"libgstgl-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-32bit-debuginfo", rpm:"libgstfft-1_0-0-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-32bit-debuginfo", rpm:"gstreamer-plugins-base-32bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-32bit", rpm:"libgstrtsp-1_0-0-32bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-lang", rpm:"gstreamer-plugins-base-lang~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-64bit", rpm:"libgstrtsp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-64bit-debuginfo", rpm:"libgstaudio-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-64bit", rpm:"libgstsdp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-64bit", rpm:"libgstgl-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-64bit", rpm:"libgstaudio-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-64bit-debuginfo", rpm:"libgstrtsp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-64bit-debuginfo", rpm:"libgstpbutils-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-64bit", rpm:"libgstfft-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-64bit", rpm:"libgstallocators-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-64bit-debuginfo", rpm:"gstreamer-plugins-base-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-64bit-debuginfo", rpm:"libgstrtp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-64bit", rpm:"libgstvideo-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-64bit", rpm:"libgstriff-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-64bit-debuginfo", rpm:"libgstfft-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-64bit", rpm:"libgstrtp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel-64bit", rpm:"gstreamer-plugins-base-devel-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-64bit", rpm:"libgstapp-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-64bit-debuginfo", rpm:"libgstallocators-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-64bit-debuginfo", rpm:"libgstvideo-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-64bit", rpm:"gstreamer-plugins-base-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-64bit-debuginfo", rpm:"libgstsdp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-64bit", rpm:"libgstpbutils-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-64bit-debuginfo", rpm:"libgstgl-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-64bit-debuginfo", rpm:"libgstriff-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-64bit-debuginfo", rpm:"libgstapp-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-64bit-debuginfo", rpm:"libgsttag-1_0-0-64bit-debuginfo~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-64bit", rpm:"libgsttag-1_0-0-64bit~1.22.0~150500.3.8.2", rls:"openSUSELeap15.5"))) {
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