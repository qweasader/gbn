###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Axis2 1.6.2 Multiple Vulnerabilities
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

CPE = "cpe:/a:apache:axis2";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111004");
  script_version("2022-08-16T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-08-16 10:20:04 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-03-17 08:00:00 +0100 (Tue, 17 Mar 2015)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2012-5785", "CVE-2012-4418", "CVE-2012-5351");

  script_name("Apache Axis2 <= 1.6.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_axis2_detect.nasl");
  script_mandatory_keys("axis2/installed");

  script_tag(name:"summary", value:"Apache Axis2 is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - a security-bypass vulnerability because the application fails to properly validate SSL
  certificates from the server.

  - a security vulnerability involving XML signature wrapping.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allows attackers to:

  - perform man-in-the-middle attacks or impersonate trusted servers, which will aid in further
  attacks.

  - may allow unauthenticated attackers to construct specially crafted messages that can be
  successfully verified and contain arbitrary content. This may aid in further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"affected", value:"The issue affects versions up to 1.6.2.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55508");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AXIS2C-1607");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version: vers, test_version: "1.6.2" ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
