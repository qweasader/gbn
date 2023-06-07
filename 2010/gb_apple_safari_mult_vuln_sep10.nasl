###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari Multiple Vulnerabilities - Sep10
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801514");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-1805", "CVE-2010-1806", "CVE-2010-1807");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities - Sep10");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4333");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43047");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43048");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43049");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010//Sep/msg00001.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to execute arbitrary code or can
  even crash the browser.");

  script_tag(name:"affected", value:"Apple Safari 5.x before 5.0.2 on Windows.");

  script_tag(name:"insight", value:"The flaws are due to

  - An use-after-free vulnerability in the application, which allows remote
    attackers to execute arbitrary code via 'run-in' styling in an element,
    related to object pointers.

  - An untrusted search path vulnerability on Windows allows local users
    to gain privileges via a Trojan horse 'explorer.exe'.

  - An error exists in the handling of 'WebKit', which does not properly
    validate floating-point data, which allows remote attackers to execute
    arbitrary cod via a crafted HTML document.");

  script_tag(name:"solution", value:"Upgrade Apple Safari 5.0.2 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.33.18.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.0.2 (output of installed version differ from actual Safari version)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
