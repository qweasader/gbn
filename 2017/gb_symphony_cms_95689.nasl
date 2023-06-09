###############################################################################
# OpenVAS Vulnerability Test
#
# Symphony CMS < 2.6.10 Cross-Site Scripting and Directory Traversal Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108048");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-5541", "CVE-2017-5542", "CVE-2017-6067");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-25 15:59:00 +0000 (Tue, 25 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-01-23 14:57:33 +0100 (Mon, 23 Jan 2017)");
  script_name("Symphony CMS < 2.6.10 Cross-Site Scripting and Directory Traversal Vulnerability");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_mandatory_keys("symphony/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.getsymphony.com/download/releases/version/2.6.10/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97101");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95686");

  script_tag(name:"summary", value:"Symphony CMS is prone to a cross-site scripting and directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attacker to:

  - execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.
  This may allow the attacker to steal cookie-based authentication credentials and to launch other attacks.

  - use a specially crafted request with directory-traversal sequences ('../') to retrieve sensitive information
  and execute arbitrary code on server side. This may aid in further attacks.");

  script_tag(name:"affected", value:"Symphony CMS versions below 2.6.10");

  script_tag(name:"solution", value:"Update to Symphony CMS 2.6.10.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.6.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.6.10" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );