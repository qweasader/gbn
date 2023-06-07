# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902189");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2010-1639", "CVE-2010-1640");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("ClamAV < 0.96.1 'cli_pdf()' and 'cli_scanicon()' DoS Vulnerabilities - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40317");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40318");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/58824");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1214");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"ClamAV is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a denial of
  service.");

  script_tag(name:"affected", value:"ClamAV version prior to 0.96.1 (1.0.26).");

  script_tag(name:"insight", value:"The flaws are due to:

  - Errors exist within the 'cli_pdf()' function in 'libclamav/pdf.c' when processing certain 'PDF'
  files. This can be exploited to cause a crash.

  - Errors exist within the 'parseicon()' function in 'libclamav/pe_icons.c' when processing 'PE'
  icons. This can be exploited to trigger an out-of-bounds access when reading data and potentially
  cause a crash.");

  script_tag(name:"solution", value:"Update to version 0.96.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port:port, cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"0.96.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.96.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
