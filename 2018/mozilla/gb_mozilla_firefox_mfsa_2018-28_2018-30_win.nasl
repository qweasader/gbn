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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814620");
  script_version("2021-07-01T02:00:36+0000");
  script_cve_id("CVE-2018-12407", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493",
                "CVE-2018-18494", "CVE-2018-18495", "CVE-2018-18496", "CVE-2018-18497",
                "CVE-2018-18498", "CVE-2018-12405", "CVE-2018-12406", "CVE-2018-18510");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-01 02:00:36 +0000 (Thu, 01 Jul 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-01 17:20:00 +0000 (Fri, 01 Mar 2019)");
  script_tag(name:"creation_date", value:"2018-12-13 11:21:11 +0530 (Thu, 13 Dec 2018)");
  script_name("Mozilla Firefox Security Update (mfsa2018-28 - mfsa2018-30) - Windows");

  script_tag(name:"summary", value:"Mozilla Firefox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow error with ANGLE library when using VertexBuffer11 module

  - Buffer overflow and out-of-bounds read in ANGLE library with TextureStorage11

  - An use-after-free error with select element

  - A buffer overflow error in accelerated 2D canvas with Skia

  - Same-origin policy violation using location attribute and performance.getEntries to steal
  cross-origin URLs

  - WebExtension content scripts can be loaded in about, in violation of the permissions granted to
  extensions

  - WebExtensions can load arbitrary URLs through pipe separators

  - An integer overflow error when calculating buffer sizes for images

  - Web content can link to internal about:crashcontent and about:crashparent pages");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to run arbitrary code,
  escalate privileges and bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before 64.0 on Windows.");

  script_tag(name:"solution", value:"Update to version 64.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-28/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-29/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-30/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"64.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"64.0", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);