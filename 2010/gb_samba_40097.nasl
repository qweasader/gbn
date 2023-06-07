###############################################################################
# OpenVAS Vulnerability Test
#
# Samba Multiple Remote Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100644");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-19 12:58:40 +0200 (Wed, 19 May 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-1635", "CVE-2010-1642");
  script_name("Samba < 3.4.8, 3.5.x < 3.5.2 Multiple Remote DoS Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40097");
  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=7229");
  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=7254");
  script_xref(name:"URL", value:"http://samba.org/samba/history/samba-3.4.8.html");
  script_xref(name:"URL", value:"http://samba.org/samba/history/samba-3.5.2.html");

  script_tag(name:"summary", value:"Samba is prone to multiple remote denial of service (DoS)
  vulnerabilities.");

  script_tag(name:"impact", value:"An attacker can exploit these issues to crash the application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"Versions prior to Samba 3.4.8 and 3.5.2 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 3.4.8, 3.5.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

if( version_is_less( version:vers, test_version:"3.4.8" ) ||
    version_in_range( version:vers, test_version:"3.5.0", test_version2:"3.5.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.4.8/3.5.2 or later", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );