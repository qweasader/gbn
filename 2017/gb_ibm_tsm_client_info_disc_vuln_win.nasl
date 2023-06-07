###############################################################################
# OpenVAS Vulnerability Test
#
# IBM TSM Client 'password' Information Disclosure Vulnerability - Windows
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:tivoli_storage_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811221");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2016-8939");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-16 02:29:00 +0000 (Tue, 16 Jan 2018)");
  script_tag(name:"creation_date", value:"2017-06-23 11:09:21 +0530 (Fri, 23 Jun 2017)");
  script_name("IBM TSM Client 'password' Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"IBM Tivoli Storage Manager Client is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to error in the IBM Tivoli
  Storage Manager (IBM Spectrum Protect) clients/agents which store password
  information in the Windows Registry in a manner which can be compromised.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Tivoli Storage Manager Client versions
  7.1 all levels, 8.1 all levels, 6.4 all levels and 6.3 and below on Windows.

  - ---
  NOTE: 6.3 and below which are all EOS.

  - ---");

  script_tag(name:"solution", value:"Workarounds and Mitigations are available.");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"qod_type", value:"executable_version_unreliable"); ## Mitigation for affected versions is available
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg22003738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98783");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_tsm_client_detect.nasl");
  script_mandatory_keys("IBM/Tivoli/Storage/Manager/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tivVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(tivVer =~ "^((7\.1)|(8\.1)|(6\.(3|4)))")
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:"Apply Mitigation");
  security_message(data:report);
  exit(0);
}
