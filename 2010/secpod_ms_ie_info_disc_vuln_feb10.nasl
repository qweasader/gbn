# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900741");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-02-26 10:13:54 +0100 (Fri, 26 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0652");
  script_name("Microsoft Internet Explorer Information Disclosure Vulnerability (Feb 2010)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_xref(name:"URL", value:"http://code.google.com/p/chromium/issues/detail?id=9877");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to obtain sensitive
  information via a crafted stylesheet document.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8 and prior.");

  script_tag(name:"insight", value:"The flaw exists while handling malformed stylesheet document
  with incorrect MIME type. Microsoft Internet Explorer permits cross-origin loading of CSS
  stylesheets even when the stylesheet download has an incorrect MIME type.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Internet Explorer is prone to an information
  disclosure vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("MS/IE/Version"))
  exit(0);

if(version_is_less_equal(version:vers, test_version:"8.0.6001.18702")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"N/A");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
