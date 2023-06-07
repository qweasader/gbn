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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4009.1");
  script_cve_id("CVE-2018-17456");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:33 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-14T02:23:29+0000");
  script_tag(name:"last_modification", value:"2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4009-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4009-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184009-1/");
  script_xref(name:"URL", value:"https://github.com/libgit2/libgit2/releases/tag/v0.26.8");
  script_xref(name:"URL", value:"https://github.com/libgit2/libgit2/releases/tag/v0.26.7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libgit2' package(s) announced via the SUSE-SU-2018:4009-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libgit2 fixes the following issues:

Security issue fixed:
CVE-2018-17456: Submodule URLs and paths with a leading '-' are now
 ignored to avoid injecting options into library consumers that perform
 recursive clones (bsc#1110949).


Non-security issues fixed:
Version update to version 0.26.8 (bsc#1114729).

Full changelog can be found at:
 * [link moved to references]
 * [link moved to references]");

  script_tag(name:"affected", value:"'libgit2' package(s) on SUSE Linux Enterprise Module for Development Tools 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26", rpm:"libgit2-26~0.26.8~3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-26-debuginfo", rpm:"libgit2-26-debuginfo~0.26.8~3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-debugsource", rpm:"libgit2-debugsource~0.26.8~3.8.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgit2-devel", rpm:"libgit2-devel~0.26.8~3.8.1", rls:"SLES15.0"))) {
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
