###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities-01 July15 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Updated By: Rajat Mishra <rajatm@secpod.com> on 2018-02-21
# - Updated to include Installation path in the report.
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805935");
  script_version("2022-04-14T06:42:08+0000");
  script_cve_id("CVE-2015-1271", "CVE-2015-1273", "CVE-2015-1274", "CVE-2015-1276",
                "CVE-2015-1279", "CVE-2015-1280", "CVE-2015-1281", "CVE-2015-1282",
                "CVE-2015-1283", "CVE-2015-1284", "CVE-2015-1286", "CVE-2015-1287",
                "CVE-2015-1270", "CVE-2015-1272", "CVE-2015-1277", "CVE-2015-1278",
                "CVE-2015-1285", "CVE-2015-1288", "CVE-2015-1289", "CVE-2015-5605",
                "CVE-2015-1290");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 06:42:08 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-02 14:20:00 +0000 (Fri, 02 Feb 2018)");
  script_tag(name:"creation_date", value:"2015-07-23 14:49:13 +0530 (Thu, 23 Jul 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-01 July15 (Mac OS X)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple heap based buffer-overflow in pdfium.

  - An error which allows executable files to run immediately after download.

  - A use-after-free error in IndexedDB.

  - A memory corruption error in skia.

  - An error allowing content security policy (CSP) bypass.

  - A use-after-free error in pdfium.

  - A heap based buffer-overflow in expat.

  - A use-after-free error in blink.

  - Universal cross-site scripting (UXSS) error in blink.

  - An error in cascading style sheets (CSS) allowing to bypass same origin
  policy.

  - Uninitialized memory read error in ICU.

  - A use-after-free error related to unexpected GPU process termination.

  - A use-after-free error in accessibility.

  - An error leading to URL spoofing using pdf files.

  - An error leading to information leak in XSS auditor.

  - An error allowing spell checking dictionaries to be fetched over HTTP.

  - The regular-expression implementation in Google V8 mishandles interrupts.

  - Various other unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security restrictions, cause a denial of service condition
  or potentially execute arbitrary code, conduct spoofing attack, gain sensitive
  information and other unspecified impacts.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  44.0.2403.89 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  44.0.2403.89 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/07/stable-channel-update_21.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75973");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76007");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"44.0.2403.89"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"44.0.2403.89", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
