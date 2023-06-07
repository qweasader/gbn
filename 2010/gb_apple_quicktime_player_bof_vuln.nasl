###############################################################################
# OpenVAS Vulnerability Test
#
# QuickTime Player Streaming Debug Error Logging Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:quicktime";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801427");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-1799");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("QuickTime Player Streaming Debug Error Logging Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41962");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/40729");
  script_xref(name:"URL", value:"http://telussecuritylabs.com/threats/show/FSC20100727-08");
  script_xref(name:"URL", value:"http://en.community.dell.com/support-forums/virus-spyware/f/3522/t/19340212.aspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_mandatory_keys("QuickTime/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a stack-based buffer
  overflow by tricking a user into viewing a specially crafted web page that
  references a SMIL file containing an overly long URL.");

  script_tag(name:"affected", value:"QuickTime Player version prior to 7.6.7.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error in 'QuickTimeStreaming.qtx' when
  constructing a string to write to a debug log file.");

  script_tag(name:"solution", value:"Upgrade to QuickTime Player version 7.6.7 or later.");

  script_tag(name:"summary", value:"QuickTime Player is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.6.7")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.6.7", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
