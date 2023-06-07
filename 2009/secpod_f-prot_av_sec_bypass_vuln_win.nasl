# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:f-prot:f-prot_antivirus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900554");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1783");
  script_name("F-PROT AntiVirus Security Bypass Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_f-prot_av_detect_win.nasl");
  script_mandatory_keys("F-Prot/AV/Win/Installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass the malware detection and
  to execute arbitrary code.");
  script_tag(name:"affected", value:"F-PROT AV version 6.0.9.1 and prior on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an error in the file parsing engine while
  processing specially crafted CAB files.");
  script_tag(name:"solution", value:"Upgrade to F-PROT AV version 6.0.9.3 or later");
  script_tag(name:"summary", value:"F-PROT AntiVirus is prone to a security bypass vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34896");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/advisory-f-prot-frisk-cab-bypass.html");
  script_xref(name:"URL", value:"http://www.f-prot.com/");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"6.0.9.1" ) ){
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.9.3", install_path:path);
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );