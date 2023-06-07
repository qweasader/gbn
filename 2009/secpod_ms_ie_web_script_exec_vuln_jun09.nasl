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

if(description)
{
  script_xref(name:"URL", value:"http://research.microsoft.com/apps/pubs/default.aspx?id=79323");
  script_xref(name:"URL", value:"http://research.microsoft.com/pubs/79323/pbp-final-with-update.pdf");
  script_oid("1.3.6.1.4.1.25623.1.0.900366");
  script_version("2022-02-25T14:06:46+0000");
  script_cve_id("CVE-2009-2057", "CVE-2009-2064", "CVE-2009-2069");
  script_tag(name:"last_modification", value:"2022-02-25 14:06:46 +0000 (Fri, 25 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-06-17 17:54:48 +0200 (Wed, 17 Jun 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Microsoft Internet Explorer Web Script Execution Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  web script and spoof an arbitrary https site by letting a browser obtain a valid certificate.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version prior to 8.0.");

  script_tag(name:"insight", value:"- Error exists while the HTTP Host header to determine the context of a
  document provided in a '4xx' or '5xx' CONNECT response from a proxy server,
  and these can be exploited by modifying the CONNECT response, aka an 'SSL tampering' attack.

  - Displays a cached certificate for a '4xx' or '5xx' CONNECT response page
  returned by a proxy server, which can be exploited by sending the browser
  a crafted 502 response page upon a subsequent request.");

  script_tag(name:"solution", value:"Upgrade to latest version.");

  script_tag(name:"summary", value:"Internet Explorer is prone to multiple web script execution vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_is_less(version:ieVer, test_version:"8.0")) {
  report = report_fixed_ver(installed_version:ieVer, fixed_version:"8.0");
  security_message(port: 0, data: report);
}
else if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18782")) {
  report = report_fixed_ver(installed_version:ieVer, vulnerable_range:"8.0 - 8.0.6001.18782");
  security_message(port: 0, data: report);
}
