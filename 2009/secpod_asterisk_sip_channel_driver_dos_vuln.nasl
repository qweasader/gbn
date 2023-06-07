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

CPE = 'cpe:/a:digium:asterisk';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900834");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2726");
  script_name("Asterisk SIP Channel Driver Denial Of Service Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Ver", "Asterisk-PBX/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36227/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36015");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2229");
  script_xref(name:"URL", value:"http://labs.mudynamics.com/advisories/MU-200908-01.txt");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2009-005.html");
  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2009-005-1.2.diff.txt");
  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2009-005-1.4.diff.txt");
  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2009-005-trunk.diff.txt");
  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2009-005-1.6.0.diff.txt");
  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2009-005-1.6.1.diff.txt");
  script_xref(name:"URL", value:"http://downloads.digium.com/pub/security/AST-2009-005-1.6.2.diff.txt");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause Denial of Service
  in the victim's system.");

  script_tag(name:"affected", value:"Asterisk version 1.2.x before 1.2.34, 1.4.x before 1.4.26.1,
  1.6.0.x before 1.6.0.12, and 1.6.1.x before 1.6.1.4 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to an error in SIP channel driver which fails to use
  maximum width when invoking 'sscanf' style functions. This can be exploited via SIP packets containing
  large sequences of ASCII decimal characters as demonstrated via vectors related to the CSeq value in a
  SIP header, large Content-Length value and SDP.");

  script_tag(name:"summary", value:"Asterisk is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"solution", value:"Upgrade to version 1.2.34, 1.4.26.1, 1.6.0.12, 1.6.1.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];

if (version_in_range( version:version, test_version:"1.2", test_version2:"1.2.33" ) ||
    version_in_range( version:version, test_version:"1.4", test_version2:"1.4.26" ) ||
    version_in_range( version:version, test_version:"1.6.0", test_version2:"1.6.0.11" ) ||
    version_in_range( version:version, test_version:"1.6.1", test_version2:"1.6.1.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"1.2.34/1.4.26.1/1.6.0.12/1.6.1.4" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );