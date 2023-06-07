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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150701");
  script_version("2021-08-17T14:01:00+0000");
  script_tag(name:"last_modification", value:"2021-08-17 14:01:00 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-06-21 09:34:21 +0000 (Mon, 21 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)");

  script_cve_id("CVE-2020-13817", "CVE-2020-11868");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NTP < 4.2.8p14 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl", "gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_tag(name:"summary", value:"NTP prior to version 4.2.8p14 and 4.3.100 is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the vulnerabilities.");

  script_tag(name:"affected", value:"NTPd version prior to 4.2.8p14, 4.3.0 through 4.3.99.");

  script_tag(name:"solution", value:"Update to version 4.2.8p14, 4.3.100 or later.");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3610");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3596");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3592");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"4.2.8p14" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.2.8p14", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"4.3.0", test_version2:"4.3.99" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.3.100", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
