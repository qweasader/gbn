# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.876638");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2019-10207", "CVE-2019-13631", "CVE-2019-12817", "CVE-2019-11477",
                "CVE-2019-11479", "CVE-2019-11478", "CVE-2019-10126", "CVE-2019-12614",
                "CVE-2019-12456", "CVE-2019-12455", "CVE-2019-12454", "CVE-2019-12378",
                "CVE-2019-3846", "CVE-2019-12380", "CVE-2019-12381", "CVE-2019-12382",
                "CVE-2019-12379", "CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130",
                "CVE-2019-11091", "CVE-2019-11884", "CVE-2019-3900", "CVE-2019-13648");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 12:20:00 +0000 (Thu, 28 Oct 2021)");
  script_tag(name:"creation_date", value:"2019-08-06 02:23:45 +0000 (Tue, 06 Aug 2019)");
  script_name("Fedora Update for kernel FEDORA-2019-7aecfe1c4b");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC30");

  script_xref(name:"FEDORA", value:"2019-7aecfe1c4b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/7JN2WSSO27GCIS47Z64ETAOLTZIYEKIB");

  script_tag(name:"summary", value:"The remote host is missing an update for the
  'kernel' package(s) announced via the FEDORA-2019-7aecfe1c4b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is
  present on the target host.");

  script_tag(name:"insight", value:"The kernel meta package");

  script_tag(name:"affected", value:"'kernel' package(s) on Fedora 30.");

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

if(release == "FC30") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.2.5~200.fc30", rls:"FC30"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
