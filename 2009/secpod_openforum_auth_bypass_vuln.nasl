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
  script_oid("1.3.6.1.4.1.25623.1.0.900927");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7066");
  script_name("OpenForum 'profile.php' Authentication Bypass Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32536");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46969");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_openforum_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openforum/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  security restrictions and modified user and password parameters.");

  script_tag(name:"affected", value:"OpenForum version 0.66 Beta and prior.");

  script_tag(name:"insight", value:"The 'profile.php' script fails to restrict access to the admin
  function which can be exploited via a direct request with the update parameter set to 1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"OpenForum is prone to an authentication bypass vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("version_func.inc");

opnfrmPort = http_get_port(default:80);

opnfrmVer = get_kb_item("www/" + opnfrmPort + "/OpenForum");
opnfrmVer = eregmatch(pattern:"^(.+) under (/.*)$", string:opnfrmVer);

if(opnfrmVer[1] != NULL)
{
  if(version_is_less_equal(version:opnfrmVer[1], test_version:"0.66.Beta")){
     security_message(opnfrmPort);
   }
}
