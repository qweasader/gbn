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
  script_oid("1.3.6.1.4.1.25623.1.0.143415");
  script_version("2022-07-20T10:33:02+0000");
  script_tag(name:"last_modification", value:"2022-07-20 10:33:02 +0000 (Wed, 20 Jul 2022)");
  script_tag(name:"creation_date", value:"2020-01-29 04:39:40 +0000 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-14302");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RICOH Printers 'CVE-2019-14302' Debug Port Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ricoh_printer_consolidation.nasl");
  script_mandatory_keys("ricoh/printer/detected");

  script_tag(name:"summary", value:"Multiple RICOH printers and multifunction printers are prone to
  a vulnerability where a debug port can be used.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Multiple RICOH printers and Multifunction Printers (MFPs). For
  a detailed list see the referenced vendor advisory.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for updated firmware versions.");

  script_xref(name:"URL", value:"https://www.ricoh.com/info/2019/0823_1/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_array("cpe:/o:ricoh:sp_210su_firmware",   "1.06",
                      "cpe:/o:ricoh:sp_210su_q_firmware", "1.06",
                      "cpe:/o:ricoh:sp_210sf_firmware",   "1.06",
                      "cpe:/o:ricoh:sp_210sf_q_firmware", "1.06",
                      "cpe:/o:ricoh:sp_211sf_firmware",   "1.06",
                      "cpe:/o:ricoh:sp_211su_firmware",   "1.06",
                      "cpe:/o:ricoh:sp_210_firmware",     "1.06",
                      "cpe:/o:ricoh:sp_210_q_firmware",   "1.02",
                      "cpe:/o:ricoh:sp_210e_firmware",    "1.02",
                      "cpe:/o:ricoh:sp_211_firmware",     "1.06");

test_list = make_list();

foreach cpe (keys(cpe_list))
  test_list = make_list(test_list, cpe);

if (!infos = get_app_version_from_list(cpe_list: test_list, nofork: TRUE))
  exit(0);

cpe = infos["cpe"];

fix = cpe_list[cpe];
if (!fix)
  exit(0);

version = infos["version"];

if (version_is_less(version: version, test_version: fix)) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
