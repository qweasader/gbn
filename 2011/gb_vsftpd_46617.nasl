###############################################################################
# OpenVAS Vulnerability Test
#
# vsftpd FTP Server 'ls.c' Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:beasts:vsftpd';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103101");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-0762");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-03-03 13:33:12 +0100 (Thu, 03 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("vsftpd FTP Server 'ls.c' Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("sw_vsftpd_detect.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("vsftpd/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46617");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd/Changelog.txt");
  script_xref(name:"URL", value:"https://security.appspot.com/vsftpd.html");

  script_tag(name:"solution", value:"A fixed version 2.3.3 is available. Please see the references for more information.");

  script_tag(name:"summary", value:"The 'vsftpd' FTP server is prone to a remote denial-of-service
  vulnerability.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows remote attackers to crash
  the affected application, denying service to legitimate users.");

  script_tag(name:"affected", value:"vsftpd versions 2.3.2 and below are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.0", test_version2:"2.3.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.3.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
