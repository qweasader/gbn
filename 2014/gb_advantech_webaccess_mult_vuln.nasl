###############################################################################
# OpenVAS Vulnerability Test
#
# Advantech WebAccess Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:advantech:advantech_webaccess";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804430");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-0763", "CVE-2014-0764", "CVE-2014-0765", "CVE-2014-0766",
                "CVE-2014-0767", "CVE-2014-0768", "CVE-2014-0770", "CVE-2014-0771",
                "CVE-2014-0772", "CVE-2014-0773");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-04-16 14:52:28 +0530 (Wed, 16 Apr 2014)");
  script_name("Advantech WebAccess Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Advantech WebAccess is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- Certain input related to some SOAP requests is not properly sanitised within
 the DBVisitor.dll component before being used in a SQL query.

  - Multiple boundary errors within the webvact.ocx ActiveX control when
  handling GotoCmd, NodeName2, AccessCode, UserName, and NodeName strings
  can be exploited to cause stack-based buffer overflows.

  - A boundary error within the webvact.ocx ActiveX control when handling the
  AccessCode2 string can be exploited to cause a stack-based buffer overflow.

  - Two errors within the 'OpenUrlToBuffer()' and 'OpenUrlToBufferTimeout()'
  methods of the BWOCXRUN.BwocxrunCtrl.1 ActiveX control can be exploited
  to disclose contents of arbitrary local or network resources.

  - An error within the 'CreateProcess()' method of the BWOCXRUN.BwocxrunCtrl.1
  ActiveX control can be exploited to bypass the intended restrictions and
  subsequently execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct SQL injection attacks,
  bypass certain security restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"Advantech WebAccess before 7.2");
  script_tag(name:"solution", value:"Upgrade to Advantech WebAccess 7.2 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66732");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66733");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66750");
  script_xref(name:"URL", value:"http://ics-cert.us-cert.gov/advisories/ICSA-14-079-03");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_advantech_webaccess_consolidation.nasl");
  script_mandatory_keys("advantech/webaccess/detected");

  exit(0);
}

include( "version_func.inc" );
include( "host_details.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port ) )
  exit( 0 );

path = infos["location"];
vers = infos["version"];

if( version_is_less( version: vers, test_version: "7.2" ) ) {
  report = report_fixed_ver( installed_version: vers, fixed_version: "7.2", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}
exit( 99 );
