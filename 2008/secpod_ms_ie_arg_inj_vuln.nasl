# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900187");
  script_version("2021-08-18T10:41:57+0000");
  script_tag(name:"last_modification", value:"2021-08-18 10:41:57 +0000 (Wed, 18 Aug 2021)");
  script_tag(name:"creation_date", value:"2008-12-31 15:44:52 +0100 (Wed, 31 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-5750");
  script_name("Microsoft Internet Explorer Argument Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7566");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_chrome.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary codes with
  the user privileges and cause argument injection in the context of the vulnerable application.");

  script_tag(name:"affected", value:"Microsoft, Internet Explorer version 8 beta 2 and prior.");

  script_tag(name:"insight", value:"The flaw is due to lack of sanitization check of user supplied input which
  causes remote command execution in the context of the application via

  - -renderer-path option in a chromehtml: URI.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host has installed Internet Explorer and is prone to Argument
  Injection vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

if(version_in_range(version:ieVer, test_version:"8.0", test_version2:"8.0.6001.18241")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
