# Copyright (C) 2016 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:dropbear_ssh_project:dropbear_ssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807740");
  script_version("2021-09-20T09:01:50+0000");
  script_cve_id("CVE-2016-3116");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:26:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:50 +0530 (Wed, 06 Apr 2016)");
  script_name("Dropbear SSH < 2016.72 CRLF Injection Vulnerability");

  script_tag(name:"summary", value:"Dropbear SSH is prone to a CRLF injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to invalid processing
  of 'X11' forwarding input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote authenticated users to inject commands to xauth.");

  script_tag(name:"affected", value:"Dropbear SSH before 2016.72.");

  script_tag(name:"solution", value:"Update to Dropbear SSH version 2016.72 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/CHANGES");
  script_xref(name:"URL", value:"https://github.com/tintinweb/pub/tree/master/pocs/cve-2016-3116");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_dropbear_consolidation.nasl");
  script_mandatory_keys("dropbear_ssh/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"2016.72" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2016.72", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
