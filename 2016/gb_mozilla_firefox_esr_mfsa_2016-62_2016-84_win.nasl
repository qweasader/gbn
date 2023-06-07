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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808642");
  script_version("2022-09-20T10:11:40+0000");
  script_cve_id("CVE-2016-5265", "CVE-2016-5264", "CVE-2016-5263", "CVE-2016-2837",
                "CVE-2016-5262", "CVE-2016-5259", "CVE-2016-5258", "CVE-2016-5254",
                "CVE-2016-5252", "CVE-2016-2836", "CVE-2016-2838", "CVE-2016-2830");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-08-08 14:54:21 +0530 (Mon, 08 Aug 2016)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2016-62_2016-84) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The nsDisplayList::HitTest function mishandles rendering display transformation.

  - The Use-after-free vulnerability in the nsNodeUtils::NativeAnonymousChildListChange
    function.

  - The Use-after-free vulnerability in the WebRTC socket thread.

  - The Use-after-free vulnerability in the CanonicalizeXPCOMParticipant function.

  - The Use-after-free vulnerability in the nsXULPopupManager::KeyDown function.

  - The Stack-based buffer underflow in the mozilla::gfx::BasePoint4d function.

  - The Heap-based buffer overflow in the nsBidi::BracketData::AddOpening function.

  - Multiple unspecified vulnerabilities in the browser engine.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  to bypass the same origin policy, to conduct Universal XSS (UXSS) attacks, to
  execute arbitrary code or cause a denial of service and to obtain sensitive
  information.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 45.x before 45.3.");

  script_tag(name:"solution", value:"Update to version 45.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-80/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-79/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-78/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-77/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-76/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-73/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"45.0", test_version2:"45.2")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"45.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);