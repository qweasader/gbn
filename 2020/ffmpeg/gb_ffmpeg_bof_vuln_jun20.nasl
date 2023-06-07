# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113706");
  script_version("2021-07-07T11:00:41+0000");
  script_tag(name:"last_modification", value:"2021-07-07 11:00:41 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2020-06-18 08:24:17 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 17:41:00 +0000 (Fri, 18 Sep 2020)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-14212");

  script_name("FFmpeg <= 4.3 Buffer Overflow Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_ffmpeg_detect_lin.nasl");
  script_mandatory_keys("FFmpeg/Linux/Ver");

  script_tag(name:"summary", value:"FFmpeg is prone to a heap-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists in avio_get_str in libavformat/aviobuf.c
  because dnn_backend_native.c calls ff_dnn_load_model_native and a certain index check is omitted.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  crash the application or execute arbitrary code on the target machine.");

  script_tag(name:"affected", value:"FFmpeg through version 4.3.");

  script_tag(name:"solution", value:"Update to version 4.4 or later.");

  script_xref(name:"URL", value:"https://trac.ffmpeg.org/ticket/8716");

  exit(0);
}

CPE = "cpe:/a:ffmpeg:ffmpeg";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.4", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
