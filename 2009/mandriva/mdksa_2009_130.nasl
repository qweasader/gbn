# OpenVAS Vulnerability Test
#
# Auto-generated from advisory MDVSA-2009:130 (gstreamer0.10-plugins-good)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64181");
  script_version("2022-01-20T13:25:39+0000");
  script_tag(name:"last_modification", value:"2022-01-20 13:25:39 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2009-06-09 19:38:29 +0200 (Tue, 09 Jun 2009)");
  script_cve_id("CVE-2009-1932");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Mandrake Security Advisory MDVSA-2009:130 (gstreamer0.10-plugins-good)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/rpms", re:"ssh/login/release=MNDK_(2008\.1|2009\.0|2009\.1)");
  script_tag(name:"insight", value:"Multiple integer overflows in the (1) user_info_callback,
(2) user_endrow_callback, and (3) gst_pngdec_task functions
(ext/libpng/gstpngdec.c) in GStreamer Good Plug-ins (aka
gst-plugins-good or gstreamer-plugins-good) 0.10.15 allow remote
attackers to cause a denial of service and possibly execute arbitrary
code via a crafted PNG file, which triggers a buffer overflow
(CVE-2009-1932).

Affected: 2008.1, 2009.0, 2009.1");
  script_tag(name:"solution", value:"To upgrade automatically use MandrakeUpdate or urpmi. The verification
of md5 checksums and GPG signatures is performed automatically for you.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:130");
  script_tag(name:"summary", value:"The remote host is missing an update to gstreamer0.10-plugins-good
announced via advisory MDVSA-2009:130.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"gstreamer0.10-aalib", rpm:"gstreamer0.10-aalib~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-caca", rpm:"gstreamer0.10-caca~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-dv", rpm:"gstreamer0.10-dv~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-esound", rpm:"gstreamer0.10-esound~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-flac", rpm:"gstreamer0.10-flac~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-good", rpm:"gstreamer0.10-plugins-good~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-raw1394", rpm:"gstreamer0.10-raw1394~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-speex", rpm:"gstreamer0.10-speex~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-wavpack", rpm:"gstreamer0.10-wavpack~0.10.7~3.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-aalib", rpm:"gstreamer0.10-aalib~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-caca", rpm:"gstreamer0.10-caca~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-dv", rpm:"gstreamer0.10-dv~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-esound", rpm:"gstreamer0.10-esound~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-flac", rpm:"gstreamer0.10-flac~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-good", rpm:"gstreamer0.10-plugins-good~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-pulse", rpm:"gstreamer0.10-pulse~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-raw1394", rpm:"gstreamer0.10-raw1394~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-soup", rpm:"gstreamer0.10-soup~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-speex", rpm:"gstreamer0.10-speex~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-wavpack", rpm:"gstreamer0.10-wavpack~0.10.10~2.2mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-aalib", rpm:"gstreamer0.10-aalib~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-caca", rpm:"gstreamer0.10-caca~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-dv", rpm:"gstreamer0.10-dv~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-esound", rpm:"gstreamer0.10-esound~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-flac", rpm:"gstreamer0.10-flac~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-plugins-good", rpm:"gstreamer0.10-plugins-good~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-pulse", rpm:"gstreamer0.10-pulse~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-raw1394", rpm:"gstreamer0.10-raw1394~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-soup", rpm:"gstreamer0.10-soup~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-speex", rpm:"gstreamer0.10-speex~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gstreamer0.10-wavpack", rpm:"gstreamer0.10-wavpack~0.10.14~1.1mdv2009.1", rls:"MNDK_2009.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99);
}
