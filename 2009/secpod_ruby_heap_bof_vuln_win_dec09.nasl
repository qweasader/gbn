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

CPE = "cpe:/a:ruby-lang:ruby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900725");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4124");
  script_name("Ruby Interpreter Heap Overflow Vulnerability (Windows) - Dec09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ruby_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ruby/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37660");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37278");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3471");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2009/12/07/heap-overflow-in-string");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, corrupt
  the heap area to execute the crafted malicious shellcode into the system
  registers to take control over the remote machine.");

  script_tag(name:"affected", value:"Ruby Interpreter version 1.9.1 before 1.9.1 Patchlevel 376.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization check while processing user
  supplied input data to the buffer inside 'String#ljust', 'String#center' and 'String#rjust' methods.");

  script_tag(name:"summary", value:"Ruby Interpreter is prone to a heap overflow vulnerability.");

  script_tag(name:"solution", value:"Update to 1.9.1 Patchlevel 376 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_in_range( version:vers, test_version:"1.9.1", test_version2:"1.9.1.375" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.9.1.p376", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
