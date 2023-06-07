###############################################################################
# OpenVAS Vulnerability Test
#
# CVSTrac text output formatter DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:cvstrac:cvstrac";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80015");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2007-0347");
  script_xref(name:"OSVDB", value:"31935");
  script_name("CVSTrac < 2.0.1 DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("cvstrac_detect.nasl");
  script_mandatory_keys("cvstrac/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/458455/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22296");

  script_tag(name:"solution", value:"Update to version 2.0.1 or later.");

  script_tag(name:"summary", value:"CVSTrac is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"insight", value:"According to its version number, the version of installed on
  the remote host contains a flaw related to its Wiki-style text output formatter.");

  script_tag(name:"impact", value:"This flaw may allow an attacker to cause a partial DoS, depending
  on the pages requested.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( ereg( pattern:"^([01]\.|2\.0\.0[^0-9.]?)", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );