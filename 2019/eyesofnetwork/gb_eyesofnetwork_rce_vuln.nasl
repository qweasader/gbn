# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114121");
  script_version("2021-09-07T08:01:28+0000");
  script_tag(name:"last_modification", value:"2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-08-20 14:48:12 +0200 (Tue, 20 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-23 15:09:00 +0000 (Tue, 23 Feb 2021)");

  script_cve_id("CVE-2019-14923");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Eyes Of Network (EON) Remote Command Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_eyesofnetwork_detect.nasl");
  script_mandatory_keys("eyesofnetwork/detected");

  script_tag(name:"summary", value:"Eyes Of Network (EON) is prone to a remote command execution vulnerability.");

  script_tag(name:"insight", value:"Eyes Of Network allows remote command execution via shell metacharacters in
  the module /tool_all/host field.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Eyes Of Network (EON) versions 5.1 and below are vulnerable.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/47280");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:eyes_of_network:eyes_of_network";

if(!version = get_app_version(cpe: CPE, nofork:TRUE))
  exit(0);

if(version_is_less_equal(version: version, test_version: "5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
