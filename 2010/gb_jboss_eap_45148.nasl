# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:redhat:jboss_enterprise_application_platform";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100931");
  script_version("2022-03-31T06:17:58+0000");
  script_tag(name:"last_modification", value:"2022-03-31 06:17:58 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2010-12-02 19:42:22 +0100 (Thu, 02 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2010-3708", "CVE-2010-3862", "CVE-2010-3878");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Red Hat JBoss Enterprise Application Platform (EAP) <= 4.3.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_red_hat_jboss_eap_http_detect.nasl", "gb_red_hat_jboss_eap_http_detect.nasl");
  script_mandatory_keys("redhat/jboss/eap/detected");

  script_tag(name:"summary", value:"Red Hat JBoss Enterprise Application Platform (EAP) is prone to
  multiple vulnerabilities, including a remote code execution (RCE) issue, a remote denial of
  service (DoS) issue, and a cross-site request forgery (CSRF) issue.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploits can allow attackers to execute arbitrary code
  within the context of the affected application, perform certain administrative actions, deploy
  arbitrary WAR files on the server, or cause denial of service conditions, other attacks may also
  be possible.");

  script_tag(name:"affected", value:"Red Hat JBoss EAP version 4.3.0. Other versions may also be
  affected.");

  script_tag(name:"solution", value:"Updates are available, please see the references for more
  information.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( "cp" >< vers )
  vers = str_replace( string:vers, find:"cp", replace:"." );

if( "GA" >< vers )
  vers = vers - ".GA";

if( version_is_less( version:vers, test_version:"4.3.0.9" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.3.0.9" );
  security_message( port:port, data:report);
  exit( 0 );
}

exit( 99 );
