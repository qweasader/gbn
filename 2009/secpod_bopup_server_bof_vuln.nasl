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
  script_oid("1.3.6.1.4.1.25623.1.0.900687");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2227");
  script_name("Bopup Communication Server Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9002");
  script_xref(name:"URL", value:"http://secunia.com/advisories/product/25643/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1645");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_bopup_server_detect.nasl");
  script_mandatory_keys("Bopup/Server/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code with
  SYSTEM privileges or can crash an affected server.");
  script_tag(name:"affected", value:"Bopup Communications Server version 3.2.26.5460 and prior");
  script_tag(name:"insight", value:"The flaw is due to a boundary error that can be exploited to cause
  a stack-based buffer overflow via a specially crafted TCP packet sent to
  port 19810.");
  script_tag(name:"solution", value:"Upgrade to Bopup Communications Server version 3.3.14.8456 or later");
  script_tag(name:"summary", value:"Bopup Communication Server is prone to a buffer overflow vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

bopupPort = 19810;
if(!get_port_state(bopupPort)){
  exit(0);
}

bopupVer = get_kb_item("Bopup/Server/Ver");
if(bopupVer != NULL)
{
  if(version_is_less_equal(version:bopupVer, test_version:"3.2.26.5460")){
    report = report_fixed_ver(installed_version:bopupVer, vulnerable_range:"Less than or equal to 3.2.26.5460");
    security_message(port: bopupPort, data: report);
  }
}
