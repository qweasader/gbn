# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803636");
  script_version("2021-10-19T13:54:28+0000");
  script_tag(name:"last_modification", value:"2021-10-19 13:54:28 +0000 (Tue, 19 Oct 2021)");
  script_tag(name:"creation_date", value:"2013-06-06 12:57:30 +0530 (Thu, 06 Jun 2013)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-2067");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat Session Fixation Vulnerability (Nov 2012) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/tomcat/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a session fixation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"java/org/apache/catalina/authenticator/FormAuthenticator.java
  in the form authentication feature does not properly handle the relationships between
  authentication requirements and sessions, which allows remote attackers to inject a request into
  a session by sending this request during completion of the login form, a variant of a session
  fixation attack.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct session
  fixation attacks to hijack the target user's session.");

  script_tag(name:"affected", value:"Apache Tomcat version 6.0.21 through 6.0.36 and 7.x through
  7.0.32.");

  script_tag(name:"solution", value:"Update to version 6.0.37, 7.0.33 or later.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/84154");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1417891");
  script_xref(name:"URL", value:"http://svn.apache.org/viewvc?view=revision&revision=1408044");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"6.0.21", test_version2:"6.0.36" ) ||
    version_in_range( version:vers, test_version:"7.0.0", test_version2:"7.0.32" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.0.37/7.0.33", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
