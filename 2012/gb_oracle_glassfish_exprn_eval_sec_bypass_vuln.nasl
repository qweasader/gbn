###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle GlassFish Server Expression Evaluation Security Bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802927");
  script_version("2022-04-27T12:01:52+0000");
  script_cve_id("CVE-2011-4358");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-27 12:01:52 +0000 (Wed, 27 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-08-07 13:44:27 +0530 (Tue, 07 Aug 2012)");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle GlassFish Server Expression Evaluation Security Bypass Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/49956/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50846");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46959/");
  script_xref(name:"URL", value:"http://java.net/jira/browse/JAVASERVERFACES-2247");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2012verbose-392736.html#Oracle%20Sun%20Products%20Suit");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("GlassFish_detect.nasl");
  script_mandatory_keys("GlassFish/installed");
  script_require_ports("Services/www", 8080);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
script code in the browser of an unsuspecting user in the context of an affected application.");

  script_tag(name:"affected", value:"Oracle GlassFish Server version 3.0.1 and 3.1.1");

  script_tag(name:"insight", value:"An unspecified error in the application, allows remote attackers to bypass
certain security restrictions.");

  script_tag(name:"summary", value:"Oracle GlassFish Server is prone to a security bypass vulnerability.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_equal(version: version, test_version: "3.0.1") ||
    version_is_equal(version: version, test_version: "3.1.1")) {
  security_message(port);
  exit(0);
}

exit(99);
