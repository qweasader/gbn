###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox 'keygen' HTML Tag DOS Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800625");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-1828", "CVE-2009-1827");
  script_name("Mozilla Firefox 'keygen' HTML Tag DOS Vulnerability - Linux");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8794");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35132");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50721");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/advisory-firefox-denial-of-service.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to cause the browser
to stop responding, infinite loop, application hang, and memory consumption,
and can cause denying service to legitimate users.");
  script_tag(name:"affected", value:"Mozilla Firefox version 3.0.4 and 3.0.10.");
  script_tag(name:"insight", value:"Flaws are due to:

  - Error exists via KEYGEN element in conjunction with a META element
   specifying automatic page refresh or a JavaScript onLoad event handler
   for a BODY element.

  - Error caused while passing a large value in the r (aka Radius) attribute
   of a circle element, related to an 'unclamped loop.'.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Mozilla Firefox is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_is_equal(version:version, test_version:"3.0.10") ||
   version_is_equal(version:version, test_version:"3.0.4")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
