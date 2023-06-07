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
  script_oid("1.3.6.1.4.1.25623.1.0.902103");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-0384");
  script_name("Tor Clients Information Disclosure Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38198");
  script_xref(name:"URL", value:"http://archives.seul.org/or/announce/Jan-2010/msg00000.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_tor_detect_lin.nasl");
  script_mandatory_keys("Tor/Linux/Ver");

  script_tag(name:"affected", value:"Tor version 0.2.2.x before 0.2.2.7-alpha on Linux.");

  script_tag(name:"insight", value:"The issue is due to directory mirror which does not prevent logging of the
  client IP address upon detection of erroneous client behavior, which might make
  it easier for local users to discover the identities of clients by reading log files.");

  script_tag(name:"solution", value:"Upgrade to version 0.2.2.7-alpha.");

  script_tag(name:"summary", value:"Tor is prone to an information disclosure vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to obtain client IP information
  that can help them launch further attacks.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

torVer = get_kb_item("Tor/Linux/Ver");
if(!torVer){
  exit(0);
}

torVer = ereg_replace(pattern:"-", replace:".", string:torVer);
if(torVer =~ "^0\.2\.2\."){
  if(version_is_less(version:torVer, test_version:"0.2.2.7.alpha")){
    report = report_fixed_ver(installed_version:torVer, fixed_version:"0.2.2.7.alpha");
    security_message(port: 0, data: report);
    exit(0);
  }
}
