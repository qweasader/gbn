##############################################################################
# OpenVAS Vulnerability Test
#
# MODX CMS Multiple Vulnerabilities
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

CPE = 'cpe:/a:modx:revolution';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106459");
  script_version("2021-10-13T12:01:28+0000");
  script_tag(name:"last_modification", value:"2021-10-13 12:01:28 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-12-09 11:42:44 +0700 (Fri, 09 Dec 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-14 20:04:00 +0000 (Thu, 14 Nov 2019)");

  script_cve_id("CVE-2016-10037", "CVE-2016-10038", "CVE-2016-10039");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MODX CMS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_modx_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("modx_cms/installed");

  script_tag(name:"summary", value:"MODX Revolution CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MODX Revolution CMS is prone to multiple vulnerabilities:

  - Critical settings visible in MODx.config

  - Local file inclusion/traversal/manipulation

  - Unauthenticated access to processors

  - Path traversal in modConnectorResponse action param");

  script_tag(name:"impact", value:"An attacker access or manipulate files on the system.");

  script_tag(name:"affected", value:"Version 2.5.1 and prior.");

  script_tag(name:"solution", value:"Update to version 2.5.2");

  script_xref(name:"URL", value:"https://raw.githubusercontent.com/modxcms/revolution/v2.5.2-pl/core/docs/changelog.txt");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13170");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13176");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13175");
  script_xref(name:"URL", value:"https://github.com/modxcms/revolution/pull/13173");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "2.5.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
