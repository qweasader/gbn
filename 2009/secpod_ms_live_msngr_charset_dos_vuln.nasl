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

CPE = "cpe:/a:microsoft:windows_live_messenger";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900461");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-02-26 05:27:20 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0647");
  script_name("Microsoft MSN Live Messneger Denial of Service Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/501043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33825");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_win_live_messenger_detect.nasl");
  script_mandatory_keys("MS/LiveMessenger/Installed");

  script_tag(name:"affected", value:"Microsoft Live Messenger version 14.0.8064.206 and prior.");

  script_tag(name:"insight", value:"This flaw is due to failure in handling charset of the message which user
  sends.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft MSN Live Messenger is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can cause denial of service.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ))
  exit(0);

vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"14.0.8064.0206" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"None", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
