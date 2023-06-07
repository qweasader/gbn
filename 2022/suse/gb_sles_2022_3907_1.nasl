# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3907.1");
  script_cve_id("CVE-2021-3522");
  script_tag(name:"creation_date", value:"2022-11-09 04:35:19 +0000 (Wed, 09 Nov 2022)");
  script_version("2022-11-09T10:31:49+0000");
  script_tag(name:"last_modification", value:"2022-11-09 10:31:49 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 16:21:00 +0000 (Wed, 09 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3907-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3907-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223907-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-base' package(s) announced via the SUSE-SU-2022:3907-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-base fixes the following issues:

CVE-2021-3522: Fixed ID3v2 tag frame size check and potential invalid
 reads (bsc#1185448).");

  script_tag(name:"affected", value:"'gstreamer-plugins-base' package(s) on SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debuginfo", rpm:"gstreamer-plugins-base-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debugsource", rpm:"gstreamer-plugins-base-debugsource~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel", rpm:"gstreamer-plugins-base-devel~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-lang", rpm:"gstreamer-plugins-base-lang~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0", rpm:"libgstallocators-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0-debuginfo", rpm:"libgstallocators-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0", rpm:"libgstapp-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-debuginfo", rpm:"libgstapp-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0", rpm:"libgstaudio-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-debuginfo", rpm:"libgstaudio-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0", rpm:"libgstfft-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0-debuginfo", rpm:"libgstfft-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0", rpm:"libgstgl-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0-debuginfo", rpm:"libgstgl-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0", rpm:"libgstpbutils-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-debuginfo", rpm:"libgstpbutils-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0", rpm:"libgstriff-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0-debuginfo", rpm:"libgstriff-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0", rpm:"libgstrtp-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0-debuginfo", rpm:"libgstrtp-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0", rpm:"libgstrtsp-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0-debuginfo", rpm:"libgstrtsp-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0", rpm:"libgstsdp-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0-debuginfo", rpm:"libgstsdp-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0", rpm:"libgsttag-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-debuginfo", rpm:"libgsttag-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0", rpm:"libgstvideo-1_0-0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-debuginfo", rpm:"libgstvideo-1_0-0-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAllocators-1_0", rpm:"typelib-1_0-GstAllocators-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstApp-1_0", rpm:"typelib-1_0-GstApp-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAudio-1_0", rpm:"typelib-1_0-GstAudio-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGL-1_0", rpm:"typelib-1_0-GstGL-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPbutils-1_0", rpm:"typelib-1_0-GstPbutils-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtp-1_0", rpm:"typelib-1_0-GstRtp-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtsp-1_0", rpm:"typelib-1_0-GstRtsp-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstSdp-1_0", rpm:"typelib-1_0-GstSdp-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstTag-1_0", rpm:"typelib-1_0-GstTag-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstVideo-1_0", rpm:"typelib-1_0-GstVideo-1_0~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-32bit-debuginfo", rpm:"gstreamer-plugins-base-32bit-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-32bit", rpm:"libgstaudio-1_0-0-32bit~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-32bit-debuginfo", rpm:"libgstaudio-1_0-0-32bit-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-32bit", rpm:"libgsttag-1_0-0-32bit~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-32bit-debuginfo", rpm:"libgsttag-1_0-0-32bit-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-32bit", rpm:"libgstvideo-1_0-0-32bit~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-32bit-debuginfo", rpm:"libgstvideo-1_0-0-32bit-debuginfo~1.16.3~150200.4.6.2", rls:"SLES15.0SP3"))) {
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
