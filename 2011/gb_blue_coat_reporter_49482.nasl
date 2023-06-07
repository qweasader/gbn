###############################################################################
# OpenVAS Vulnerability Test
#
# Blue Coat Reporter Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103246");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-09-08 15:23:37 +0200 (Thu, 08 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Blue Coat Reporter Directory Traversal Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_blue_coat_reporter_detect.nasl");
  script_mandatory_keys("bluecoat/reporter/detected");
  script_require_ports("Services/www", 80);
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Blue Coat Reporter is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to view arbitrary local
  files within the context of the Web server. Information harvested may
  aid in launching further attacks.");

  script_tag(name:"affected", value:"Blue Coat Reporter versions prior to 9.3 are vulnerable.");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49482");
  script_xref(name:"URL", value:"http://www.bluecoat.com/products/reporter/index.html");
  script_xref(name:"URL", value:"http://www.bluecoat.com");
  script_xref(name:"URL", value:"https://kb.bluecoat.com/index?page=content&id=SA60");
  exit(0);
}

CPE = "cpe:/a:bluecoat:reporter";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_is_less(version:vers, test_version:"9.3.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.3.1.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
