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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809392");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5276", "CVE-2016-5274",
                "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5284",
                "CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5281");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-12 01:29:00 +0000 (Tue, 12 Jun 2018)");
  script_tag(name:"creation_date", value:"2016-10-21 15:34:45 +0530 (Fri, 21 Oct 2016)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2016-88_2016-88) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString.

  - Bad cast in nsImageGeometryMixin.

  - Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList.

  - Use-after-free in nsFrameManager::CaptureFrameState.

  - Use-after-free in DOMSVGLength.

  - Heap-use-after-free in nsRefreshDriver::Tick.

  - Heap-buffer-overflow in nsBMPEncoder::AddImageFrame.

  - Use-after-free in mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap.

  - Add-on update site certificate pin expiration.

  - Resource Timing API is storing resources sent by the previous page.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to cause denial of service, to get a
  mis-issued certificate for a Mozilla web sit could send malicious add-on updates
  to users on networks controlled by the attacker, to get potential
  information, also allows to run arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before 45.4.");

  script_tag(name:"solution", value:"Update to version 45.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-88/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93049");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92260");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_portable_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"45.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"45.4", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);