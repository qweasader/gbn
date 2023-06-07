# Copyright (C) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902291");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2010-4327");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Novell eDirectory NCP Request Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("novell_edirectory_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed", "Host/runs_unixoide"); # only eDirectory running under Linux is affected

  script_xref(name:"URL", value:"http://secunia.com/advisories/43186");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46263");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0305");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-060/");
  script_xref(name:"URL", value:"http://www.novell.com/support/viewContent.do?externalId=7007781&sliceId=2");

  script_tag(name:"insight", value:"This flaw is caused by an error in the 'NCP' implementation when processing
  malformed 'FileSetLock' requests sent to port 524.");

  script_tag(name:"solution", value:"Upgrade to Novell eDirectory 8.8.5.6 or 8.8.6.2.");

  script_tag(name:"summary", value:"Novell eDirectory is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a vulnerable
  service to become unresponsive, leading to a denial of service condition.");

  script_tag(name:"affected", value:"Novell eDirectory 8.8.5 before 8.8.5.6 (8.8.5.SP6)
  Novell eDirectory 8.8.6 before 8.8.6.2 (8.8.6.SP2) on Linux.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:novell:edirectory", "cpe:/a:netiq:edirectory" );

if( ! infos = get_app_port_from_list( cpe_list:cpe_list ) )
  exit( 0 );

cpe  = infos["cpe"];
port = infos["port"];

if( ! major = get_app_version( cpe:cpe, port:port ) )
  exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

instvers = major;

if( sp > 0 )
  instvers += ' SP' + sp;

edirVer = major + '.' + sp;

if(version_in_range(version:edirVer, test_version:"8.8.5", test_version2:"8.8.5.5") ||
   version_in_range(version:edirVer, test_version:"8.8.6", test_version2:"8.8.6.1")) {
  report = report_fixed_ver( installed_version:instvers, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
