# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147226");
  script_version("2021-11-26T14:03:50+0000");
  script_tag(name:"last_modification", value:"2021-11-26 14:03:50 +0000 (Fri, 26 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-26 03:20:48 +0000 (Fri, 26 Nov 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-16 18:39:00 +0000 (Tue, 16 Nov 2021)");

  script_cve_id("CVE-2021-34419");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Zoom Client < 5.1.0 HTML Injection Vulnerability (ZSB-21015) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_ssh_login_linux_detect.nasl");
  script_mandatory_keys("zoom/client/lin/detected");

  script_tag(name:"summary", value:"The Zoom Client is prone to an HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There is an HTML injection flaw when sending a remote control
  request to a user in the process of in-meeting screen sharing. This could allow meeting
  participants to be targeted for social engineering attacks.");

  script_tag(name:"affected", value:"Zoom Client prior to version 5.1.0 on Ubuntu.");

  script_tag(name:"solution", value:"Update to version 5.1.0 or later.");

  script_xref(name:"URL", value:"https://explore.zoom.us/en/trust/security/security-bulletin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "5.1.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.1.0", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
