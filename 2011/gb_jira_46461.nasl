###############################################################################
# OpenVAS Vulnerability Test
#
# Atlassian JIRA Unspecified URI Redirection Vulnerability
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

CPE = "cpe:/a:atlassian:jira";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103085");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Atlassian JIRA Unspecified URI Redirection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_jira_http_detect.nasl");
  script_mandatory_keys("atlassian/jira/detected");

  script_tag(name:"summary", value:"Atlassian JIRA is prone to a URI-redirect vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Atlassian JIRA is prone to a URI-redirection vulnerability because the
application fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"A successful exploit may aid in phishing attacks. Other attacks are
also possible.");

  script_tag(name:"affected", value:"Versions prior to Atlassian JIRA 4.2.2 are vulnerable.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46461");
  script_xref(name:"URL", value:"http://www.atlassian.com/software/jira/");
  script_xref(name:"URL", value:"http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2011-02-21");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.2.2")) {
   report = report_fixed_ver(installed_version: version, fixed_version: "4.2.2");
   security_message(port: port, data: report);
   exit(0);
}

exit(0);
