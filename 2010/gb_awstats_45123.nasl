###############################################################################
# OpenVAS Vulnerability Test
#
# Awstats Configuration File Remote Arbitrary Command Execution Vulnerability
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

CPE = "cpe:/a:awstats:awstats";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100925");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
  script_cve_id("CVE-2010-4367", "CVE-2010-4368");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Awstats Configuration File Remote Arbitrary Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45123");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/870532");
  script_xref(name:"URL", value:"http://www.exploitdevelopment.com/Vulnerabilities/2010-WEB-001.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("awstats_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("awstats/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Awstats is prone to an arbitrary command-execution vulnerability. This issue
  is due to a failure in the application to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to execute arbitrary shell commands
  in the context of the webserver process. This may help attackers compromise the underlying system. Other attacks
  are also possible.");

  script_tag(name:"affected", value:"Awstats < 7.0 is vulnerable.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: vers, test_version: "6.95")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "7.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
