# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114138");
  script_version("2023-02-23T10:19:58+0000");

  script_cve_id("CVE-2019-10401", "CVE-2019-10402", "CVE-2019-10403",
                "CVE-2019-10404", "CVE-2019-10405", "CVE-2019-10406");

  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-02-23 10:19:58 +0000 (Thu, 23 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:44:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-07 14:21:04 +0200 (Mon, 07 Oct 2019)");

  script_name("Jenkins < 2.197 and < 2.176.4 LTS Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2019-09-25/");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - The f:expandableTextBox form control interpreted its content as HTML when expanded, resulting in
  a stored XSS vulnerability exploitable by users with permission to define its contents, typically
  Job/Configure. (CVE-2019-10401)

  - The f:combobox form control interpreted its item labels as HTML, resulting in a stored XSS
  vulnerability exploitable by users with permission to define its contents. (CVE-2019-10402)

  - The SCM tag name on the tooltip for SCM tag actions was not being escaped, resulting in a stored
  XSS vulnerability exploitable by users able to control SCM tag names for these actions. (CVE-2019-10403)

  - The reason why a queue item is blocked in tooltips was not being escaped, resulting in a stored
  XSS vulnerability exploitable by users able to control parts of the reason a queue item is blocked,
  such as label expressions not matching any idle executors. (CVE-2019-10404)

  - The value of the 'Cookie' HTTP request header on the /whoAmI/ URL was being printed, allowing
  attackers exploiting another XSS vulnerability to obtain the HTTP session cookie despite it being
  marked as HttpOnly. (CVE-2019-10405)

  - The values set as Jenkins URL in the global configuration were not being restricted or filtered,
  resulting in a stored XSS vulnerability exploitable by attackers with Overall/Administer permission.
  (CVE-2019-10406)");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.176.3, Jenkins weekly up to and including 2.196.");

  script_tag(name:"solution", value:"Update Jenkins weekly to version 2.197 or later / Jenkins LTS to
  version 2.176.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_full(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if(get_kb_item("jenkins/" + port + "/is_lts")) {
  if(version_is_less(version: version, test_version: "2.176.4")) {
    vuln = TRUE;
    fix = "2.176.4";
  }
} else {
  if(version_is_less(version: version, test_version: "2.197")) {
    vuln = TRUE;
    fix = "2.197";
  }
}

if(vuln) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
