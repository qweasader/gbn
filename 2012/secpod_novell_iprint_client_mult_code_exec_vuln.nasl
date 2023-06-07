# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:novell:iprint";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902674");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-4185", "CVE-2011-4186", "CVE-2011-4187");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-04-26 12:20:02 +0530 (Thu, 26 Apr 2012)");
  script_name("Novell iPrint Client Multiple Remote Code Execution Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47867/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51926");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026660");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7010143");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7010144");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7010145");
  script_xref(name:"URL", value:"http://www.novell.com/support/kb/doc.php?id=7008708");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_novell_prdts_detect_win.nasl");
  script_mandatory_keys("Novell/iPrint/Installed");
  script_tag(name:"insight", value:"The flaws are due to

  - An error in nipplib.dll within the 'GetDriverSettings()' function.

  - An error within the 'GetPrinterURLList2()' function in the ActiveX Control,
    when handling overly long string parameters.

  - A boundary error within nipplib.dll, when parsing the 'client-file-name'
    parameter.");
  script_tag(name:"solution", value:"Upgrade to the Novell iPrint Client version 5.78 or later.");
  script_tag(name:"summary", value:"Novell iPrint Client is prone to multiple remote code execution vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code,
  cause buffer overflow or a denial of service condition.");
  script_tag(name:"affected", value:"Novell iPrint Client version prior to 5.78");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://download.novell.com/Download?buildid=6_bNby38ERg~");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"5.78" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.78", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
