###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - 01 June14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804616");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746",
                "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3152",
                "CVE-2014-3803");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-06-04 09:39:42 +0530 (Wed, 04 Jun 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 June14 (Windows)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to:

  - A use-after-free error exists in 'StyleElement::removedFromDocument' function
within core/dom/StyleElement.cpp.

  - An integer overflow error exists in 'AudioInputRendererHost::OnCreateStream'
function in media/audio_input_renderer_host.cc.

  - A use-after-free error exists within SVG.

  - An error within media filters  in 'InMemoryUrlProtocol::Read'.

  - An error in 'DocumentLoader::maybeCreateArchive' function related to a local
MHTML file.

  - An error in 'ScrollView::paint' function related to scroll bars.

  - Multiple unspecified errors exist.

  - An integer overflow error in 'LCodeGen::PrepareKeyedOperand' function in
arm/lithium-codegen-arm.cc within v8.

  - Some error in speech API within Blink.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a denial of
service, inject arbitrary web script or HTML, spoof the UI, enable microphone
access and obtain speech-recognition text and possibly have other unspecified
impact.");
  script_tag(name:"affected", value:"Google Chrome version prior to 35.0.1916.114 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 35.0.1916.114 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/05/stable-channel-update_20.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67517");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67582");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67790");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"35.0.1916.114"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"35.0.1916.114");
  security_message(port:0, data:report);
  exit(0);
}
