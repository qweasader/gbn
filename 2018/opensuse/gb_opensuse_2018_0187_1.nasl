# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851686");
  script_version("2023-11-03T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2018-01-24 07:43:17 +0100 (Wed, 24 Jan 2018)");
  script_cve_id("CVE-2017-5715", "CVE-2018-2676", "CVE-2018-2685", "CVE-2018-2686",
                "CVE-2018-2687", "CVE-2018-2688", "CVE-2018-2689", "CVE-2018-2690",
                "CVE-2018-2693", "CVE-2018-2694", "CVE-2018-2698");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for virtualbox (openSUSE-SU-2018:0187-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'virtualbox'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for virtualbox to version 5.1.32 fixes the following issues:

  The following vulnerabilities were fixed (boo#1076372):

  - CVE-2017-5715: Systems with microprocessors utilizing speculative
  execution and indirect branch prediction may allow unauthorized
  disclosure of information to an attacker with local user access via a
  side-channel analysis, also known as 'Spectre', bsc#1068032.

  - CVE-2018-2676: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2685: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2686: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2687: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2688: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2689: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2690: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2693: Local authenticated attacker may gain elevated privileges
  via guest additions

  - CVE-2018-2694: Local authenticated attacker may gain elevated privileges

  - CVE-2018-2698: Local authenticated attacker may gain elevated privileges

  The following bug fixes are included:

  - fix occasional screen corruption when host screen resolution is changed

  - increase proposed disk size when creating new VMs for Windows 7 and newer

  - fix broken communication with certain devices on Linux hosts

  - Fix problems using 256MB VRAM in raw-mode VMs

  - add HDA support for more exotic guests (e.g. Haiku)

  - fix playback with ALSA backend (5.1.28 regression)

  - fix a problem where OHCI emulation might sporadically drop data transfers");

  script_tag(name:"affected", value:"virtualbox on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0187-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox-debuginfo", rpm:"python-virtualbox-debuginfo~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.1.32_k4.4.104_18.44~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default-debuginfo", rpm:"virtualbox-guest-kmp-default-debuginfo~5.1.32_k4.4.104_18.44~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.1.32_k4.4.104_18.44~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default-debuginfo", rpm:"virtualbox-host-kmp-default-debuginfo~5.1.32_k4.4.104_18.44~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.1.32~19.49.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox", rpm:"python-virtualbox~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualbox-debuginfo", rpm:"python-virtualbox-debuginfo~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox", rpm:"virtualbox~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debuginfo", rpm:"virtualbox-debuginfo~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-debugsource", rpm:"virtualbox-debugsource~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-devel", rpm:"virtualbox-devel~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default", rpm:"virtualbox-guest-kmp-default~5.1.32_k4.4.104_39~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-kmp-default-debuginfo", rpm:"virtualbox-guest-kmp-default-debuginfo~5.1.32_k4.4.104_39~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools", rpm:"virtualbox-guest-tools~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-tools-debuginfo", rpm:"virtualbox-guest-tools-debuginfo~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11", rpm:"virtualbox-guest-x11~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-x11-debuginfo", rpm:"virtualbox-guest-x11-debuginfo~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default", rpm:"virtualbox-host-kmp-default~5.1.32_k4.4.104_39~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-kmp-default-debuginfo", rpm:"virtualbox-host-kmp-default-debuginfo~5.1.32_k4.4.104_39~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt", rpm:"virtualbox-qt~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-qt-debuginfo", rpm:"virtualbox-qt-debuginfo~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-vnc", rpm:"virtualbox-vnc~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv", rpm:"virtualbox-websrv~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-websrv-debuginfo", rpm:"virtualbox-websrv-debuginfo~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-desktop-icons", rpm:"virtualbox-guest-desktop-icons~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-guest-source", rpm:"virtualbox-guest-source~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"virtualbox-host-source", rpm:"virtualbox-host-source~5.1.32~42.1", rls:"openSUSELeap42.3"))) {
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
