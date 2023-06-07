##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update-for-desktop_24-2018-01)-Windows
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812674");
  script_version("2021-10-11T09:46:29+0000");
  script_cve_id("CVE-2018-6031", "CVE-2018-6032", "CVE-2018-6033", "CVE-2018-6034",
                "CVE-2018-6035", "CVE-2018-6036", "CVE-2018-6037", "CVE-2018-6038",
                "CVE-2018-6039", "CVE-2018-6040", "CVE-2018-6041", "CVE-2018-6042",
                "CVE-2018-6043", "CVE-2018-6045", "CVE-2018-6046", "CVE-2018-6047",
                "CVE-2018-6048", "CVE-2018-6049", "CVE-2018-6050", "CVE-2018-6051",
                "CVE-2018-6052", "CVE-2018-6053", "CVE-2018-6054", "CVE-2018-6055",
                "CVE-2018-6119");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-11 09:46:29 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-20 17:34:00 +0000 (Tue, 20 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-01-25 16:11:22 +0530 (Thu, 25 Jan 2018)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop_24-2018-01)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use after free error in PDFium.

  - Same origin bypass in Shared Worker.

  - Race condition when opening downloaded files.

  - Integer overflow error and referrer policy bypass in Blink.

  - Insufficient isolation of devtools from extensions.

  - Integer underflow in WebAssembly.

  - Insufficient user gesture requirements in autofill.

  - Heap buffer overflow and cross origin URL leak in WebGL.

  - XSS in DevTools.

  - Content security policy bypass.

  - URL spoof in Navigation and OmniBox.

  - Insufficient escaping with external URL handlers.

  - UI spoof in Permissions.

  - Referrer leak in XSS Auditor.

  - Incomplete no-referrer policy implementation.

  - Leak of page thumbnails in New Tab Page.

  - Use after free in WebUI.

  - Incorrect security UI in Omnibox.

  - Insufficient policy enforcement in Catalog Service.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary script, conduct spoofing attack and cause some
  unspecified impact.");

  script_tag(name:"affected", value:"Google Chrome version prior to 64.0.3282.119
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 64.0.3282.119
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/01/stable-channel-update-for-desktop_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
chr_ver  = infos['version'];
chrPath = infos['location'];

if(version_is_less(version:chr_ver, test_version:"64.0.3282.119"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"64.0.3282.119", install_path:chrPath);
  security_message(data:report);
  exit(0);
}
exit(0);
