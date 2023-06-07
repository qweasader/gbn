# Copyright (C) 2020 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143349");
  script_version("2022-02-15T10:35:00+0000");
  script_tag(name:"last_modification", value:"2022-02-15 10:35:00 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2020-01-13 06:45:21 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-21 20:58:00 +0000 (Tue, 21 Jan 2020)");

  script_cve_id("CVE-2019-6332");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("HP Printers XSS Vulnerability (HPSBPI03624)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_printer_consolidation.nasl");
  script_mandatory_keys("hp/printer/detected");

  script_tag(name:"summary", value:"Multiple HP printers are vulnerable to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"HP DeskJet 2600, HP DeskJet Ink Advantage 2600, HP DeskJet Ink Advantage 5000,
  HP ENVY 5000, HP ENVY Photo 6200, HP ENVY Photo 7100, HP ENVY Photo 7800, HP Ink Tank Wireless 410 series,
  HP OfficeJet 5200 and HP Smart Tank Wireless 450 series Printers.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://support.hp.com/in-en/document/c06428029");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:hp:deskjet_2600_firmware",
                     "cpe:/o:hp:ink_tank_wireless_410_firmware",
                     "cpe:/o:hp:smart_tank_wireless_450_firmware");

if (!infos = get_app_port_from_list(cpe_list: cpe_list))
  exit(0);

cpe = infos["cpe"];

if (!version = get_app_version(cpe: cpe, nofork: TRUE))
  exit(0);

version = toupper(version);

if (cpe == "cpe:/o:hp:deskjet_2600_firmware") {
  if (version_is_less(version: version, test_version: "TJP1FN1923AR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "TJP1FN1923AR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:ink_tank_wireless_410_firmware") {
  if (version_is_less(version: version, test_version: "KEP1FN1924CR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "KEP1FN1924CR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (cpe == "cpe:/o:hp:smart_tank_wireless_450_firmware") {
  if (version_is_less(version: version, test_version: "KDP1FN1924CR")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "KDP1FN1924CR");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
