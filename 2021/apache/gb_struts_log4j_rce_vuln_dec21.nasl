# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147309");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2021-12-13 04:31:37 +0000 (Mon, 13 Dec 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-44228");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("Apache Struts 2.5.x Log4j RCE Vulnerability (Log4Shell) - Version Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution (RCE)
  vulnerability in the Apache Log4j library dubbed 'Log4Shell'.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Log4j2 JNDI features used in configuration, log messages,
  and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.
  An attacker who can control log messages or log message parameters can execute arbitrary code
  loaded from LDAP servers when message lookup substitution is enabled.");

  script_tag(name:"affected", value:"Apache Struts version 2.5.x.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a workaround.");

  script_xref(name:"URL", value:"https://struts.apache.org/announce-2021#a20211212-2");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-jfh8-c2jp-5v3q");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/10/1");
  script_xref(name:"URL", value:"https://www.lunasec.io/docs/blog/log4j-zero-day/");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# TODO: Update when patch is available. From the Struts announcement about Log4j 2.15.0 containing a fix:
# This version of Log4j requires Java 8, while Apache Struts 2.5.x series is still using Java 1.7 and because of that we cannot prepare a new patched 2.5.x version.
if (version =~ "^2\.5\.") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
