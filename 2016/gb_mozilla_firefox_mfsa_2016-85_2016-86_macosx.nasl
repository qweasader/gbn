# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809325");
  script_version("2021-10-13T08:01:25+0000");
  script_cve_id("CVE-2016-2827", "CVE-2016-5270", "CVE-2016-5271", "CVE-2016-5272",
                "CVE-2016-5273", "CVE-2016-5276", "CVE-2016-5274", "CVE-2016-5277",
                "CVE-2016-5275", "CVE-2016-5278", "CVE-2016-5279", "CVE-2016-5280",
                "CVE-2016-5281", "CVE-2016-5282", "CVE-2016-5283", "CVE-2016-5284",
                "CVE-2016-5256", "CVE-2016-5257");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-13 08:01:25 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-12 01:29:00 +0000 (Tue, 12 Jun 2018)");
  script_tag(name:"creation_date", value:"2016-09-23 10:24:26 +0530 (Fri, 23 Sep 2016)");
  script_name("Mozilla Firefox Security Update (mfsa_2016-85_2016-86) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Out-of-bounds read in mozilla::net::IsValidReferrerPolicy.

  - Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString.

  - Out-of-bounds read in PropertyProvider::GetSpacingInternal.

  - Bad cast in nsImageGeometryMixin.

  - Crash in mozilla::a11y::HyperTextAccessible::GetChildOffset.

  - Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList.

  - Use-after-free in nsFrameManager::CaptureFrameState.

  - Heap-use-after-free in nsRefreshDriver::Tick.

  - Global-buffer-overflow in mozilla::gfx::FilterSupport::ComputeSourceNeededRegions.

  - Heap-buffer-overflow in nsBMPEncoder::AddImageFrame.

  - Full local path of files is available to web pages after drag and drop.

  - Use-after-free in mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap.

  - Use-after-free in DOMSVGLength.

  - Favicons can be loaded through non-whitelisted protocols.

  - 'iframe src' fragment timing attack can reveal cross-origin data.

  - Add-on update site certificate pin expiration.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation of these
  vulnerabilities remote attackers to cause a denial of service, to execute
  arbitrary code, to obtain sensitive full-pathname information.");

  script_tag(name:"affected", value:"Mozilla Firefox versions before 49.");

  script_tag(name:"solution", value:"Update to version 49 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-85/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"49")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"49", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);