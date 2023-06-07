# Copyright (C) 2008 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900403");
  script_version("2022-05-11T11:17:52+0000");
  script_cve_id("CVE-2007-5000", "CVE-2007-6388");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-02 11:52:55 +0100 (Tue, 02 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("HP OpenView Network Node Manager XSS Vulnerability");
  script_dependencies("os_detection.nasl", "secpod_hp_openview_nnm_detect.nasl");
  script_require_ports("Services/www", 7510);
  script_mandatory_keys("HP/OVNNM/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://secunia.com/Advisories/32800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/26838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/27237");

  script_tag(name:"summary", value:"HP OpenView Network Node Manager is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"insight", value:"The flaws are due to errors in HP OpenView NNM 'Network Node Manager'
  program.");

  script_tag(name:"affected", value:"HP OpenView Network Node Manager versions 7.01, 7.51 and 7.53 on HP-UX, Linux,
  and Solaris.");

  script_tag(name:"solution", value:"Apply available patches or updates released by the vendor.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary codes.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.01" ) ||
    version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );