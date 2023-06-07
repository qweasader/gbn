# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = 'cpe:/a:oxid:eshop';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900933");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2009-3112");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OXID eShop Community Edition Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/385006.php");
  script_xref(name:"URL", value:"http://www.oxidforge.org/wiki/Security_bulletins/2009-001");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_oxid_eshop_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("oxid_eshop/installed");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain administrator privileges and
  access shop backend via specially crafted URLs.");

  script_tag(name:"affected", value:"OXID eShop Community Edition version 4.0 prior to 4.1.0.");

  script_tag(name:"insight", value:"User supplied data passed to an unspecified variable is not sanitised
  before processing.");

  script_tag(name:"solution", value:"Apply the patches or upgrade to version 4.1.0.");

  script_tag(name:"summary", value:"OXID eShop Community Edition is prone to a privilege escalation vulnerability.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^4\.") {
  if (version_is_less(version: version,test_version:"4.1.0")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.1.0");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
