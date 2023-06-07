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

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100150");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-04-17 18:35:24 +0200 (Fri, 17 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-0163");
  script_name("CUPS '_cupsImageReadTIFF()' Integer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_cups_detect.nasl");
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34571");
  script_xref(name:"URL", value:"http://www.cups.org/str.php?L3031");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code
  with the privileges of a user running the utilities. Failed exploit attempts likely cause
  denial-of-service conditions.");

  script_tag(name:"affected", value:"CUPS versions prior to 1.3.10.");

  script_tag(name:"solution", value:"Update to version 1.3.10 or later.");

  script_tag(name:"summary", value:"CUPS (Common UNIX Printing System) service is prone to an
  integer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.3.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.3.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );