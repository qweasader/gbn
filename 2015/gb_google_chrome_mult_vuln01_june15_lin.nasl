###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities-01 June15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805667");
  script_version("2021-10-21T13:57:32+0000");
  script_cve_id("CVE-2015-1269", "CVE-2015-1268", "CVE-2015-1267", "CVE-2015-1266");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-21 13:57:32 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-06-29 17:03:23 +0530 (Mon, 29 Jun 2015)");
  script_name("Google Chrome Multiple Vulnerabilities-01 June15 (Linux)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - 'DecodeHSTSPreloadRaw' function in 'net/http/transport_security_state.cc'
  script does not properly canonicalize DNS hostnames before making comparisons
  to HSTS or HPKP preload entries.

  - 'bindings/scripts/v8_types.py' in Blink does not properly select a creation
  context for a return value's DOM wrapper.

  - Blink does not properly restrict the creation context during creation of a
  DOM wrapper.

  - 'content/browser/webui/content_web_ui_controller_factory.cc' script does not
  properly consider the scheme in determining whether a URL is associated with a
  WebUI SiteInstance.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the Same Origin Policy and intended access restrictions
  via different dimensions.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  43.0.2357.130 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  43.0.2357.130 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://codereview.chromium.org/1149753002");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2015/06/chrome-stable-update.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)) exit(0);

if(version_is_less(version:chromeVer, test_version:"43.0.2357.130"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     43.0.2357.130'  + '\n';
  security_message(data:report);
  exit(0);
}
