###############################################################################
# OpenVAS Vulnerability Test
#
# McAfee ePolicy Orchestrator (ePO) Multiple Vulnerabilities-01 August13
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:mcafee:epolicy_orchestrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803864");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-0140", "CVE-2013-0141");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-08-09 14:52:18 +0530 (Fri, 09 Aug 2013)");
  script_name("McAfee ePolicy Orchestrator (ePO) Multiple Vulnerabilities-01 August13");

  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to McAfee ePolicy Orchestrator version 5.0 or 4.6.6 or 4.5.7 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaws are due to improper sanitation of user supplied input via 'uid'
parameter to /EPOAGENTMETA/DisplayMSAPropsDetail.do script and specifically
directory traversal style (e.g., ../../).");
  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator (ePO) version before 4.5.7 and 4.6.x before 4.6.6");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate
SQL queries in the back-end database, allowing for the manipulation or
disclosure of arbitrary data.");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53196");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59500");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59505");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/209131");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10042");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mcafee_epolicy_orchestrator_detect.nasl");
  script_mandatory_keys("mcafee_ePO/installed");
  script_require_ports("Services/www", 8443);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

port = get_app_port(cpe:CPE);
if(!port){
  exit(0);
}

if(!vers = get_app_version(cpe:CPE, port:port)){
  exit(0);
}

if(vers)
{
  if(version_is_less(version:vers, test_version:"4.5.7") ||
     version_in_range(version:vers, test_version:"4.6.0", test_version2:"4.6.5"))
  {
    security_message(port);
    exit(0);
  }
}
