###############################################################################
# OpenVAS Vulnerability Test
#
# BigTree CMS < 4.2.22 XSS Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:bigtreecms:bigtree_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112264");
  script_version("2021-06-07T11:00:20+0000");
  script_tag(name:"last_modification", value:"2021-06-07 11:00:20 +0000 (Mon, 07 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-05-02 13:38:22 +0200 (Wed, 02 May 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-05 18:31:00 +0000 (Tue, 05 Jun 2018)");
  script_cve_id("CVE-2018-10364");
  script_name("BigTree CMS < 4.2.22 XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bigtree_detect.nasl");
  script_mandatory_keys("bigtree_cms/detected");

  script_tag(name:"summary", value:"BigTree CMS is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"BigTree CMS has XSS in the Users management page via the name or company field.");

  script_tag(name:"affected", value:"BigTree CMS versions before 4.2.22.");

  script_tag(name:"solution", value:"Update to version 4.2.22 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://github.com/bigtreecms/BigTree-CMS/issues/332");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"4.2.22" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.2.22" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
