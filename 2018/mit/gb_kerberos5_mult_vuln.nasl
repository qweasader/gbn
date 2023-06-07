# Copyright (C) 2018 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:mit:kerberos";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113084");
  script_version("2021-06-22T02:00:27+0000");
  script_tag(name:"last_modification", value:"2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-01-17 14:14:14 +0100 (Wed, 17 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 17:15:00 +0000 (Thu, 25 Feb 2021)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2018-5709", "CVE-2018-5710");

  script_name("MIT Kerberos5 <= 1.16 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_kerberos5_ssh_login_detect.nasl");
  script_mandatory_keys("mit/kerberos5/detected");

  script_tag(name:"summary", value:"MIT Kerberos5 is prone to a Denial of Service (DoS) and an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The DoS vulnerability exists due to the possibility of causing
  a NULL pointer dereference.

  The information disclosure vulnerability exists because 32 bits are allocated to a 16-bit variable.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive
  information cause a DoS.");

  script_tag(name:"affected", value:"MIT Kerberos5 versions through 1.16.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_xref(name:"URL", value:"https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Integer%20Overflow");
  script_xref(name:"URL", value:"https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Denial%20Of%20Service%28DoS%29");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "1.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
