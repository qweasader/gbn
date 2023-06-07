###############################################################################
# OpenVAS Vulnerability Test
#
# Apple Safari 'setInterval()' Address Bar Spoofing Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802818");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-3844");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-03-13 18:17:52 +0530 (Tue, 13 Mar 2012)");
  script_name("Apple Safari 'setInterval()' Address Bar Spoofing Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44976");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52323");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026775");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73712");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct spoofing attacks via a
  crafted HTML document.");

  script_tag(name:"affected", value:"Apple Safari version 5.0.5 on Windows.");

  script_tag(name:"insight", value:"The flaw is due to an improper implementation of the setInterval
  function, which allows remote attackers to spoof the address bar via a crafted web page.");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 5.1.2 or later.");

  script_tag(name:"summary", value:"Apple Safari web browser is prone to address bar spoofing vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"5.33.21.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"Safari 5.1.2 (output of installed version differ from actual Safari version)", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
