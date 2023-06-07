# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:twistedmatrix:twisted";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147823");
  script_version("2022-03-22T14:03:54+0000");
  script_tag(name:"last_modification", value:"2022-03-22 14:03:54 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-22 02:06:54 +0000 (Tue, 22 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)");

  script_cve_id("CVE-2020-10108", "CVE-2020-10109");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Twisted Web < 20.3.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_twistedweb_http_detect.nasl");
  script_mandatory_keys("twistedweb/detected");

  script_tag(name:"summary", value:"Twisted Web is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  CVE-2020-10108: HTTP request splitting. When presented with two content-length headers, it
  ignored the first header. When the second content-length value was set to zero, the request body
  was interpreted as a pipelined request.

  CVE-2020-10109: HTTP request splittingy. When presented with a content-length and a chunked
  encoding header, the content-length took precedence and the remainder of the request body was
  interpreted as a pipelined request.");

  script_tag(name:"affected", value:"Twisted Web prior to version 20.3.0.");

  script_tag(name:"solution", value:"Update to version 20.3.0 or later.");

  script_xref(name:"URL", value:"https://bishopfox.com/blog/twisted-version-19-10-0-advisory");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "20.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "20.3.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
