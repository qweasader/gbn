###############################################################################
# OpenVAS Vulnerability Test
#
# cfengine AuthenticationDialogue vulnerability
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

CPE = "cpe:/a:gnu:cfengine";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14314");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1701", "CVE-2004-1702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10899");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10900");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CFEngine AuthenticationDialogue Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("cfengine_detect.nasl");
  script_mandatory_keys("cfengine/running");

  script_tag(name:"solution", value:"Update to version 2.1.8 or later.");

  script_tag(name:"summary", value:"CFEngine cfservd is prone to a remote heap-based buffer overrun
  vulnerability.");

  script_tag(name:"insight", value:"The vulnerability presents itself in the cfengine cfservd
  AuthenticationDialogue() function. The issue exists due to a lack of sufficient boundary checks
  performed on challenge data that is received from a client.

  In addition, cfengine cfservd is prone to a remote denial of service vulnerability. The
  vulnerability presents itself in the cfengine cfservd AuthenticationDialogue() function which is
  responsible for processing SAUTH commands and also performing RSA based authentication. The
  vulnerability presents itself because return values for several statements within the
  AuthenticationDialogue() function are not checked.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if( version_is_less( version:version, test_version:"2.1.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.1.8" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
