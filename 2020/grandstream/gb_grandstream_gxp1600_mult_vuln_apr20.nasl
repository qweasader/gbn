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
  script_oid("1.3.6.1.4.1.25623.1.0.143707");
  script_version("2021-08-17T06:00:55+0000");
  script_tag(name:"last_modification", value:"2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2020-04-15 08:54:43 +0000 (Wed, 15 Apr 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-14 17:54:00 +0000 (Tue, 14 Apr 2020)");

  script_cve_id("CVE-2020-5738", "CVE-2020-5739");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grandstream GXP1600 Series IP Phones <= 1.0.4.152 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_grandstream_gxp_consolidation.nasl");
  script_mandatory_keys("grandstream/gxp/detected");

  script_tag(name:"summary", value:"Grandstream GXP1600 Series IP Phones are prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Grandstream GXP1600 Series IP Phones are prone to multiple vulnerabilities:

  - Authenticated RCE via Tar Upload (CVE-2020-5738)

  - Authenticated RCE via OpenVPN Configuration File (CVE-2020-5739)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Grandstream GXP1600 Series IP Phones with firmware version 1.0.4.152 and
  probably prior.");

  script_tag(name:"solution", value:"Update to version 1.0.5.3 or later.");

  script_xref(name:"URL", value:"https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da");
  script_xref(name:"URL", value:"https://www.tenable.com/security/research/tra-2020-22");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/o:grandstream:gxp1610_firmware",
                     "cpe:/o:grandstream:gxp1615_firmware",
                     "cpe:/o:grandstream:gxp1620_firmware",
                     "cpe:/o:grandstream:gxp1625_firmware",
                     "cpe:/o:grandstream:gxp1628_firmware",
                     "cpe:/o:grandstream:gxp1630_firmware");

if (!infos = get_app_version_from_list(cpe_list: cpe_list, nofork: TRUE))
  exit(0);

vers = infos["version"];

if (version_is_less_equal(version: vers, test_version: "1.0.4.152")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "1.0.5.3");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
