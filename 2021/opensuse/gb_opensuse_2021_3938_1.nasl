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
  script_oid("1.3.6.1.4.1.25623.1.0.854348");
  script_version("2021-12-09T09:30:06+0000");
  script_cve_id("CVE-2021-39920", "CVE-2021-39921", "CVE-2021-39922", "CVE-2021-39924", "CVE-2021-39925", "CVE-2021-39926", "CVE-2021-39928", "CVE-2021-39929");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-12-09 09:30:06 +0000 (Thu, 09 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-23 17:25:00 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-12-07 02:03:03 +0000 (Tue, 07 Dec 2021)");
  script_name("openSUSE: Security Advisory for wireshark (openSUSE-SU-2021:3938-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:3938-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2AUQBQMT4O7Y26OSAOSJT4MNYT4MQ6ME");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the openSUSE-SU-2021:3938-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark fixes the following issues:

  - Update to Wireshark 3.4.10:

  - CVE-2021-39920: IPPUSB dissector crash (bsc#1192830).

  - CVE-2021-39921: Modbus dissector crash (bsc#1192830).

  - CVE-2021-39922: C12.22 dissector crash (bsc#1192830).

  - CVE-2021-39924: Bluetooth DHT dissector large loop (bsc#1192830).

  - CVE-2021-39925: Bluetooth SDP dissector crash (bsc#1192830).

  - CVE-2021-39926: Bluetooth HCI_ISO dissector crash (bsc#1192830).

  - CVE-2021-39928: IEEE 802.11 dissector crash (bsc#1192830).

  - CVE-2021-39929: Bluetooth DHT dissector crash (bsc#1192830).");

  script_tag(name:"affected", value:"'wireshark' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14", rpm:"libwireshark14~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark14-debuginfo", rpm:"libwireshark14-debuginfo~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11", rpm:"libwiretap11~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap11-debuginfo", rpm:"libwiretap11-debuginfo~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12", rpm:"libwsutil12~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil12-debuginfo", rpm:"libwsutil12-debuginfo~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.4.10~3.62.1", rls:"openSUSELeap15.3"))) {
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