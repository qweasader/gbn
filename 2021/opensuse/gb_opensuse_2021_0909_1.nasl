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
  script_oid("1.3.6.1.4.1.25623.1.0.853879");
  script_version("2021-08-26T09:01:14+0000");
  script_cve_id("CVE-2020-26418", "CVE-2020-26419", "CVE-2020-26420", "CVE-2020-26421", "CVE-2020-26422", "CVE-2021-22173", "CVE-2021-22174", "CVE-2021-22191", "CVE-2021-22207");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-26 09:01:14 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-09 09:15:00 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-06-25 03:01:31 +0000 (Fri, 25 Jun 2021)");
  script_name("openSUSE: Security Advisory for wireshark, (openSUSE-SU-2021:0909-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0909-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QDSEUP77D5HE3ISH2VMQR2GIAFH6DLQK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark, '
  package(s) announced via the openSUSE-SU-2021:0909-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark, libvirt, sbc and libqt5-qtmultimedia fixes the
     following issues:

     Update wireshark to version 3.4.5

  - New and updated support and bug fixes for multiple protocols

  - Asynchronous DNS resolution is always enabled

  - Protobuf fields can be dissected as Wireshark (header) fields

  - UI improvements

     Including security fixes for:

  - CVE-2021-22191: Wireshark could open unsafe URLs (bsc#1183353).

  - CVE-2021-22207: MS-WSP dissector excessive memory consumption
       (bsc#1185128)

  - CVE-2020-26422: QUIC dissector crash (bsc#1180232)

  - CVE-2020-26418: Kafka dissector memory leak (bsc#1179930)

  - CVE-2020-26419: Multiple dissector memory leaks (bsc#1179931)

  - CVE-2020-26420: RTPS dissector memory leak (bsc#1179932)

  - CVE-2020-26421: USB HID dissector crash (bsc#1179933)

  - CVE-2021-22173: Fix USB HID dissector memory leak (bsc#1181598)

  - CVE-2021-22174: Fix USB HID dissector crash (bsc#1181599)

     libqt5-qtmultimedia and sbc are necessary dependencies. libvirt is needed
     to rebuild wireshark-plugin-libvirt.");

  script_tag(name:"affected", value:"'wireshark, ' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14-debuginfo", rpm:"libwireshark14-debuginfo~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11-debuginfo", rpm:"libwiretap11-debuginfo~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12-debuginfo", rpm:"libwsutil12-debuginfo~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.4.5~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
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