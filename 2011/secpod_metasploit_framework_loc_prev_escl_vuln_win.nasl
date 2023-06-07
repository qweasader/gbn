# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.902294");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1056", "CVE-2011-1057");
  script_name("Metasploit Framework Local Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43166");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46300");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0371");
  script_xref(name:"URL", value:"http://blog.metasploit.com/2011/02/metasploit-framework-352-released.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_metasploit_framework_detect_win.nasl");
  script_mandatory_keys("Metasploit/Framework/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the local users to execute arbitrary code
  with LocalSystem privileges when the 'frameworkPostgreSQL' service is
  restarted.");
  script_tag(name:"affected", value:"Metasploit Framework version 3.5.1 and prior on windows.");
  script_tag(name:"insight", value:"The flaw is due to the application being installed with insecure
  filesystem permissions in the system's root drive. This can be exploited
  to create arbitrary files in certain directories.");
  script_tag(name:"solution", value:"Upgrade Metasploit Framework 3.5.2 or later.");
  script_tag(name:"summary", value:"Metasploit Framework is prone to a local privilege escalation vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.metasploit.com/framework/download/");
  exit(0);
}


include("version_func.inc");

mfVer = get_kb_item("Metasploit/Framework/Win/Ver");
if(mfVer)
{
  if(version_is_less(version:mfVer, test_version:"3.5.2")){
    report = report_fixed_ver(installed_version:mfVer, fixed_version:"3.5.2");
    security_message(port: 0, data: report);
  }
}
