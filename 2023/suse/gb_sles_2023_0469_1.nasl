# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0469.1");
  script_cve_id("CVE-2023-0767", "CVE-2023-25728", "CVE-2023-25729", "CVE-2023-25730", "CVE-2023-25732", "CVE-2023-25734", "CVE-2023-25735", "CVE-2023-25737", "CVE-2023-25738", "CVE-2023-25739", "CVE-2023-25742", "CVE-2023-25743", "CVE-2023-25744", "CVE-2023-25746");
  script_tag(name:"creation_date", value:"2023-03-28 13:04:06 +0000 (Tue, 28 Mar 2023)");
  script_version("2023-03-29T10:21:17+0000");
  script_tag(name:"last_modification", value:"2023-03-29 10:21:17 +0000 (Wed, 29 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0469-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0469-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230469-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2023:0469-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:
Updated to version 102.8.0 ESR (bsc#1208144):

CVE-2023-25728: Fixed content security policy leak in violation reports using iframes.
CVE-2023-25730: Fixed screen hijack via browser fullscreen mode.
CVE-2023-25743: Fixed Fullscreen notification not being shown in Firefox Focus.
CVE-2023-0767: Fixed arbitrary memory write via PKCS 12 in NSS.
CVE-2023-25735: Fixed potential use-after-free from compartment mismatch in SpiderMonkey.
CVE-2023-25737: Fixed invalid downcast in SVGUtils::SetupStrokeGeometry.
CVE-2023-25738: Fixed printing on Windows which could potentially crash Firefox with some device drivers.
CVE-2023-25739: Fixed use-after-free in mozilla::dom::ScriptLoadContext::~ScriptLoadContext.
CVE-2023-25729: Fixed extensions opening external schemes without user knowledge.
CVE-2023-25732: Fixed out of bounds memory write from EncodeInputStream.
CVE-2023-25734: Fixed opening local .url files that causes unexpected network loads.
CVE-2023-25742: Fixed tab crash by Web Crypto ImportKey.
CVE-2023-25744: Fixed Memory safety bugs.
CVE-2023-25746: Fixed Memory safety bugs.");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on SUSE CaaS Platform 4.0, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~102.8.0~150000.150.76.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~102.8.0~150000.150.76.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~102.8.0~150000.150.76.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~102.8.0~150000.150.76.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~102.8.0~150000.150.76.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~102.8.0~150000.150.76.1", rls:"SLES15.0SP1"))) {
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
