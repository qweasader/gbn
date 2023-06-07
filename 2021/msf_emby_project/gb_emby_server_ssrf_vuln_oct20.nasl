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

CPE = "cpe:/a:msf_emby_project:msf_emby";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146695");
  script_version("2021-09-10T10:01:38+0000");
  script_tag(name:"last_modification", value:"2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-10 08:37:09 +0000 (Fri, 10 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-26 15:12:00 +0000 (Mon, 26 Oct 2020)");

  script_cve_id("CVE-2020-26948");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Emby Server < 4.5.0 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_emby_server_http_detect.nasl");
  script_mandatory_keys("emby/media_server/detected");

  script_tag(name:"summary", value:"Emby Server is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Emby Server allows SSRF via the Items/RemoteSearch/Image
  ImageURL parameter.");

  script_tag(name:"affected", value:"Emby Server prior to version 4.5.0.");

  script_tag(name:"solution", value:"Update to version 4.5.0 or later.");

  script_xref(name:"URL", value:"https://github.com/btnz-k/emby_ssrf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "4.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
