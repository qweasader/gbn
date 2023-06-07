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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802758");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2009-0037", "CVE-2010-0734", "CVE-2010-1452", "CVE-2010-1623", "CVE-2010-2068",
                "CVE-2010-2791", "CVE-2010-3436", "CVE-2010-4409", "CVE-2010-4645", "CVE-2011-0014",
                "CVE-2011-0195", "CVE-2011-0419", "CVE-2011-1148", "CVE-2011-1153", "CVE-2011-1464",
                "CVE-2011-1467", "CVE-2011-1468", "CVE-2011-1470", "CVE-2011-1471", "CVE-2011-1928",
                "CVE-2011-1938", "CVE-2011-1945", "CVE-2011-2192", "CVE-2011-2202", "CVE-2011-2483",
                "CVE-2011-3182", "CVE-2011-3189", "CVE-2011-3192", "CVE-2011-3267", "CVE-2011-3268",
                "CVE-2011-3207", "CVE-2011-3210", "CVE-2011-3348", "CVE-2011-3368", "CVE-2011-3639",
                "CVE-2011-3846", "CVE-2012-0135", "CVE-2012-1993");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-04-23 13:36:33 +0530 (Mon, 23 Apr 2012)");
  script_name("HP/HPE System Management Homepage (SMH) Multiple Vulnerabilities (HPSBMU02764)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_smh_http_detect.nasl");
  script_mandatory_keys("hp/smh/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43012");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52974");
  script_xref(name:"URL", value:"https://support.hpe.com/hpesc/public/docDisplay?docLocale=en_US&docId=c03280632");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 7.0 or later.");

  script_tag(name:"summary", value:"HP/HPE System Management Homepage (SMH) is prone to multiple
  vulnerabilities.");

  script_tag(name:"affected", value:"HP/HPE SMH version 6.2.2.7 and prior.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! version = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:version, test_version:"7.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.0");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );