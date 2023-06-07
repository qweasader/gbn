# Copyright (C) 2008 Greenbone Networks GmbH
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

CPE = "cpe:/a:southrivertech:titan_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900160");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-10-23 14:16:10 +0200 (Thu, 23 Oct 2008)");
  script_cve_id("CVE-2008-6082");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("Titan FTP Server 'SITE WHO' Command Remote DoS Vulnerability");
  script_dependencies("gb_titan_ftp_detect.nasl");
  script_mandatory_keys("TitanFTP/detected");

  script_xref(name:"URL", value:"http://milw0rm.com/exploits/6753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31757");
  script_xref(name:"URL", value:"http://secunia.com/advisories/32269/");

  script_tag(name:"summary", value:"Titan FTP Server is prone to a denial of service vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to error in the 'SITE WHO' command processing, which
  can be exploited to exhaust available CPU resources.");

  script_tag(name:"affected", value:"South River Technologies Titan FTP Server versions prior to 6.26.631.");

  script_tag(name:"solution", value:"Update to version 6.26.631 or later.");

  script_tag(name:"impact", value:"Successful exploitation will cause a denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.26.631")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.26.631");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);