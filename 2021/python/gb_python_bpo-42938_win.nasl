# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118180");
  script_version("2021-09-21T14:01:15+0000");
  script_tag(name:"last_modification", value:"2021-09-21 14:01:15 +0000 (Tue, 21 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-02 10:12:49 +0200 (Thu, 02 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");

  script_cve_id("CVE-2021-3177");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 3.6.13, 3.7.x < 3.7.10, 3.8.x < 3.8.8, 3.9.x < 3.9.2 Python Issue (bpo-42938) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a buffer overflow vulnerability in
  'PyCArg_repr'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow in 'PyCArg_repr' in '_ctypes/callproc.c'
  exists, which may lead to remote code execution in certain Python applications that accept
  floating-point numbers as untrusted input, as demonstrated by a '1e300' argument to
  'c_double.from_param'. This occurs because sprintf is used unsafely.");

  script_tag(name:"affected", value:"Python prior to version 3.6.13, versions 3.7.x prior to
  3.7.10, 3.8.x prior to 3.8.8 and 3.9.x prior to 3.9.2.");

  script_tag(name:"solution", value:"Update to version 3.6.13, 3.7.10, 3.8.8, 3.9.2 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/ctypes-buffer-overflow-pycarg_repr.html");
  script_xref(name:"Advisory-ID", value:"bpo-42938");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.6.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"3.7.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.7.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.8.0", test_version2:"3.8.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.8.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.9.0", test_version2:"3.9.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
