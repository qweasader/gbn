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
  script_oid("1.3.6.1.4.1.25623.1.0.902562");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-08-31 10:37:30 +0200 (Wed, 31 Aug 2011)");
  script_cve_id("CVE-2011-3006", "CVE-2011-3007");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("McAfee SaaS Endpoint Protection ActiveX Controls Multiple Code Execution Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45506");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49087");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1025890");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10016");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_mcafee_saas_endpoint_protection_detect.nasl");
  script_mandatory_keys("McAfee/SaaS/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application running the ActiveX control.");
  script_tag(name:"affected", value:"McAfee SaaS Endpoint Protection version 5.2.1 and prior.");
  script_tag(name:"insight", value:"- An error within the MyASUtil ActiveX control (MyAsUtil5.2.0.603.dll) when
    processing the 'CreateSecureObject()' method can be exploited to inject
    and execute arbitrary commands.

  - The insecure 'Start()' method within the MyCioScan ActiveX control
    (myCIOScn.dll) can be exploited to write to arbitrary files in the context
    of the currently logged-on user.");
  script_tag(name:"solution", value:"Upgrade to McAfee SaaS Endpoint Protection version 5.2.2 or later.");
  script_tag(name:"summary", value:"McAfee SaaS Endpoint Protection is prone to multiple code execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.mcafeeasap.com/");
  exit(0);
}


include("version_func.inc");

version = get_kb_item("McAfee/SaaS/Win/Ver");
if(version)
{
  if(version_is_less(version:version, test_version:"5.2.2")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"5.2.2");
    security_message(port: 0, data: report);
  }
}
