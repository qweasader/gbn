# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853501");
  script_version("2021-08-13T09:00:57+0000");
  script_cve_id("CVE-2020-25219", "CVE-2020-26154");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-29 04:15:00 +0000 (Sun, 29 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-18 03:00:52 +0000 (Sun, 18 Oct 2020)");
  script_name("openSUSE: Security Advisory for libproxy (openSUSE-SU-2020:1680-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1680-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libproxy'
  package(s) announced via the openSUSE-SU-2020:1680-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libproxy fixes the following issues:

  - CVE-2020-25219: Rewrote url::recvline to be nonrecursive (bsc#1176410).

  - CVE-2020-26154: Fixed a buffer overflow when PAC is enabled
  (bsc#1177143).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1680=1");

  script_tag(name:"affected", value:"'libproxy' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libproxy-debugsource", rpm:"libproxy-debugsource~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-devel", rpm:"libproxy-devel~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-tools", rpm:"libproxy-tools~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-tools-debuginfo", rpm:"libproxy-tools-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1", rpm:"libproxy1~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-debuginfo", rpm:"libproxy1-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libproxy", rpm:"python-libproxy~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libproxy", rpm:"python3-libproxy~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-plugins-debugsource", rpm:"libproxy-plugins-debugsource~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy-sharp", rpm:"libproxy-sharp~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-32bit", rpm:"libproxy1-32bit~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-32bit-debuginfo", rpm:"libproxy1-32bit-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-config-gnome3", rpm:"libproxy1-config-gnome3~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-config-gnome3-debuginfo", rpm:"libproxy1-config-gnome3-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-config-kde", rpm:"libproxy1-config-kde~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-config-kde-debuginfo", rpm:"libproxy1-config-kde-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-networkmanager", rpm:"libproxy1-networkmanager~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-networkmanager-debuginfo", rpm:"libproxy1-networkmanager-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-pacrunner-webkit", rpm:"libproxy1-pacrunner-webkit~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libproxy1-pacrunner-webkit-debuginfo", rpm:"libproxy1-pacrunner-webkit-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Net-Libproxy", rpm:"perl-Net-Libproxy~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Net-Libproxy-debuginfo", rpm:"perl-Net-Libproxy-debuginfo~0.4.15~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
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