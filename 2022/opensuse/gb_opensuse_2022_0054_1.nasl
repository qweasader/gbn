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
  script_oid("1.3.6.1.4.1.25623.1.0.854515");
  script_version("2022-03-15T14:03:18+0000");
  script_cve_id("CVE-2020-29050", "CVE-2019-14511");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-15 14:03:18 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-14 16:03:00 +0000 (Fri, 14 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-03-02 02:01:14 +0000 (Wed, 02 Mar 2022)");
  script_name("openSUSE: Security Advisory for sphinx (openSUSE-SU-2022:0054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0054-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/H2Z7YY7HZ2IKSH75SHSRUFT5AJHJJOLN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sphinx'
  package(s) announced via the openSUSE-SU-2022:0054-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for sphinx fixes the following issues:

  - CVE-2020-29050: SphinxSearch in Sphinx Technologies Sphinx allows
       directory traversal (in conjunction with CVE-2019-14511) because the
       mysql client can be used for CALL SNIPPETS and load_file operations on a
       full pathname (e.g., a file in the /etc directory). (boo#1195227)

  - update to 2.0.6 release");

  script_tag(name:"affected", value:"'sphinx' package(s) on openSUSE Leap 15.3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsphinxclient-0_0_1", rpm:"libsphinxclient-0_0_1~2.2.11~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsphinxclient-devel", rpm:"libsphinxclient-devel~2.2.11~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sphinx", rpm:"sphinx~2.2.11~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sphinx-debuginfo", rpm:"sphinx-debuginfo~2.2.11~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sphinx-debugsource", rpm:"sphinx-debugsource~2.2.11~lp153.2.3.1", rls:"openSUSELeap15.3"))) {
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