###############################################################################
# OpenVAS Vulnerability Test
#
# Splunk Cross Site Scripting and Directory Traversal Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:splunk:splunk";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100694");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Splunk XSS and Directory Traversal Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/41269");
  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAFGD#31067");

  script_tag(name:"summary", value:"Splunk is prone to multiple cross-site scripting (XSS)
  vulnerabilities and multiple directory traversal vulnerabilities because it fails to sufficiently
  sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploiting these issues will allow an attacker to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site,
  and to view arbitrary local files and directories within the context of the webserver. This may
  let the attacker steal cookie-based authentication credentials and other harvested information may
  aid in launching further attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "4.0", test_version2: "4.0.10") ||
    version_in_range(version: version, test_version: "4.1", test_version2: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
