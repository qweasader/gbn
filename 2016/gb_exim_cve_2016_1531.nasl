###############################################################################
# OpenVAS Vulnerability Test
#
# Exim Local Root / Privilege Escalation Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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
###############################################################################

CPE = 'cpe:/a:exim:exim';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105568");
  script_cve_id("CVE-2016-1531");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_version("2021-09-20T10:01:48+0000");

  script_name("Exim Local Root / Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://www.exim.org/static/doc/CVE-2016-1531.txt");

  script_tag(name:"insight", value:"When Exim installation has been compiled with Perl support and contains a  perl_startup configuration variable it can be exploited by malicious local attackers to gain root privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to Exim 4.86.2 or newer.");

  script_tag(name:"summary", value:"Exim < 4.86.2 Local Root Privilege Escalation");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-08 01:29:00 +0000 (Fri, 08 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-03-15 13:17:46 +0100 (Tue, 15 Mar 2016)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_exim_detect.nasl");
  script_require_ports("Services/smtp", 25);
  script_mandatory_keys("exim/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:version, test_version:"4.86.2" ) )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:"4.86.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );


