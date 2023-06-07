###############################################################################
# OpenVAS Vulnerability Test
#
# Winmail Server < 6.3 Directory Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:magicwinmail:winmail_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141491");
  script_version("2022-05-31T14:29:50+0100");
  script_tag(name:"last_modification", value:"2022-05-31 14:29:50 +0100 (Tue, 31 May 2022)");
  script_tag(name:"creation_date", value:"2018-09-19 15:07:23 +0700 (Wed, 19 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-05 14:26:00 +0000 (Mon, 05 Feb 2018)");

  script_cve_id("CVE-2018-5700");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Winmail Server < 6.3 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_winmail_server_web_detect.nasl");
  script_mandatory_keys("winmail_server/detected");

  script_tag(name:"summary", value:"Winmail Server allows remote code execution by authenticated users who
leverage directory traversal in a netdisk.php copy_folder_file call (in inc/class.ftpfolder.php) to move a .php
file from the FTP folder into a web folder.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Winmail Server 6.2 and prior.");

  script_tag(name:"solution", value:"Update to version 6.3 or later.");

  script_xref(name:"URL", value:"https://github.com/0xWfox/Winmail/blob/master/Winmail_6.2.md");
  script_xref(name:"URL", value:"http://www.magicwinmail.net/changelog.asp");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
