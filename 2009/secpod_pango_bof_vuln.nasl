# Copyright (C) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:pango:pango";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900644");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1194");
  script_name("Pango < 1.24.0 Integer Buffer Overflow Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_pango_detect.nasl");
  script_mandatory_keys("pango/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35018");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34870");
  script_xref(name:"URL", value:"http://www.debian.org/security/2009/dsa-1798");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/05/07/1");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary code via
  a long glyph string, and can cause a denial of service.");

  script_tag(name:"affected", value:"Pango version prior to 1.24.0.");

  script_tag(name:"insight", value:"Error in pango_glyph_string_set_size function in pango/glyphstring.c file,
  which fails to perform adequate boundary checks on user-supplied data before
  using the data to allocate memory buffers.");

  script_tag(name:"solution", value:"Upgrade to pango version 1.24.0 or later.");

  script_tag(name:"summary", value:"This host has installed with Pango and is prone to an integer buffer
  overflow vulnerability.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

location = infos["location"];
version = infos["version"];

if(version_is_less(version:version, test_version:"1.24.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.24.0", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
