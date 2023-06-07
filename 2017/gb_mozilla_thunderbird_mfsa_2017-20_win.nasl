# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.811711");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-7800", "CVE-2017-7801", "CVE-2017-7809", "CVE-2017-7784",
                "CVE-2017-7802", "CVE-2017-7785", "CVE-2017-7786", "CVE-2017-7753",
                "CVE-2017-7787", "CVE-2017-7807", "CVE-2017-7792", "CVE-2017-7804",
                "CVE-2017-7791", "CVE-2017-7782", "CVE-2017-7803", "CVE-2017-7779");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-01 12:04:00 +0000 (Wed, 01 Aug 2018)");
  script_tag(name:"creation_date", value:"2017-08-21 11:51:43 +0530 (Mon, 21 Aug 2017)");
  script_name("Mozilla Thunderbird Security Update (mfsa_2017-20) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use-after-free in WebSockets during disconnection.

  - Use-after-free with marquee during window resizing.

  - Use-after-free while deleting attached editor DOM node.

  - Use-after-free with image observers.

  - Use-after-free resizing image elements.

  - Buffer overflow manipulating ARIA attributes in DOM.

  - Buffer overflow while painting non-displayable SVG.

  - Out-of-bounds read with cached style data and pseudo-elements.

  - Same-origin policy bypass with iframes through page reloads.

  - Domain hijacking through AppCache fallback.

  - Buffer overflow viewing certificates with an extremely long OID.

  - Memory protection bypass through WindowsDllDetourPatcher.

  - Spoofing following page navigation with data: protocol and modal alerts.

  - WindowsDllDetourPatcher allocates memory without DEP protections.

  - CSP containing sandbox improperly applied.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to gain access to potentially sensitive information,
  execute arbitrary code and conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird versions before 52.3.");

  script_tag(name:"solution", value:"Update to version 52.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-20/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100197");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100202");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100206");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100315");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100242");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100240");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100243");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100201");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"52.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"52.3", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);