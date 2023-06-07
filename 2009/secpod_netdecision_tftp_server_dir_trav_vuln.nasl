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
  script_oid("1.3.6.1.4.1.25623.1.0.900358");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1730");
  script_name("NetDecision TFTP Server Multiple Directory Traversal Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35131");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35002");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/50574");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/503605");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_netdecision_tftp_server_detect.nasl");
  script_mandatory_keys("NetDecision/TFTP/Ver");

  script_tag(name:"affected", value:"NetMechanica, NetDecision TFTP Server version 4.2 and prior.");

  script_tag(name:"insight", value:"Due to an input validation error within the TFTP server which
  in fails to sanitize user-supplied input in GET or PUT command via ../ (dot dot) sequences.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"NetDecision TFTP Server is prone to multiple directory traversal vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose
  sensitive information, upload or download files to and from arbitrary
  locations and compromise a vulnerable system to legitimate users.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");

netdeciVer = get_kb_item("NetDecision/TFTP/Ver");
if(!netdeciVer)
  exit(0);

if(version_is_less_equal(version:netdeciVer, test_version:"4.2")){
  security_message(port:0);
  exit(0);
}

exit(99);