###############################################################################
# OpenVAS Vulnerability Test
#
# Puppet Enterprise < 2016.4.0 Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:puppet:enterprise";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106363");
  script_version("2021-10-13T14:01:34+0000");
  script_tag(name:"last_modification", value:"2021-10-13 14:01:34 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-11-01 10:57:40 +0700 (Tue, 01 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-21 16:02:00 +0000 (Wed, 21 Apr 2021)");

  script_cve_id("CVE-2016-5714", "CVE-2016-5715", "CVE-2016-5716");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Puppet Enterprise < 2016.4.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_puppet_enterprise_detect.nasl");
  script_mandatory_keys("puppet_enterprise/installed");

  script_tag(name:"summary", value:"Puppet Enterprise is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Puppet Enterprise is prone to multiple vulnerabilities:

  - Unprivileged access to environment catalogs which may reveal sensitive information about your infrastructure
if you are using Application Orchestration. (CVE-2016-5714)

  - Remote code execution because of unsafe string reads. (CVE-2016-5716)

  - Puppet Communications Protocol (PCP) Broker String Validation Vulnerability.

  - Arbitrary URL Redirection in Puppet Enterprise Console. (CVE-2016-5715)

  - Puppet Execution Protocol (PXP) Command Whitelist Validation Vulnerability.");

  script_tag(name:"impact", value:"An attacker may execute remote code, obtain sensitive information or use it
for phishing attacks.");

  script_tag(name:"affected", value:"Puppet Enterprise 2015.x and 2016.x");

  script_tag(name:"solution", value:"Update to version 2016.4.0 or later.");

  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2016-5714");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/pe-console-oct-2016");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/pcp-broker-oct-2016");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/cve-2016-5715");
  script_xref(name:"URL", value:"https://puppet.com/security/cve/pxp-agent-oct-2016");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2016.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2016.4.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
