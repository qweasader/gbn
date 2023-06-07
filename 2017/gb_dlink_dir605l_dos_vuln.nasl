# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/o:d-link:dir-605l_firmware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112129");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-11-17 15:56:17 +0100 (Fri, 17 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-17 02:29:00 +0000 (Fri, 17 Nov 2017)");

  script_cve_id("CVE-2017-9675");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("D-Link DIR-605L < 2.08UIBetaB01 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-605L is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Firmware versions 2.08UI and lower contain a bug in the function
  that handles HTTP GET requests for directory paths that can allow an unauthenticated attacker to
  cause complete denial of service (device reboot). This bug can be triggered from both LAN
  and WAN.");

  script_tag(name:"affected", value:"D-Link DIR-605L firmware 2.08UI and prior.");

  script_tag(name:"solution", value:"Upgrade to version 2.08UIBetaB01 or later.");

  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-605L/REVB/DIR-605L_REVB_RELEASE_NOTES_v2.08UIBETAB01_EN.pdf");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99084");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/145011/D-Link-DIR605L-2.08-Denial-Of-Service.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

# cpe:/o:d-link:dir-605l_firmware:2.06
if (!fw_vers = get_app_version(cpe: CPE, port: port))
  exit(0);

# e.g. B1
if (!hw_vers = get_kb_item("d-link/dir/hw_version"))
  exit(0);

hw_vers = toupper(hw_vers);

if (hw_vers =~ "^B" && version_is_less(version: fw_vers, test_version: "2.08")) {
  report = report_fixed_ver(installed_version: fw_vers, fixed_version: "2.08UIBetaB01", extra: "Hardware revision: " + hw_vers);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
