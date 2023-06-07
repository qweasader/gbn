###############################################################################
# OpenVAS Vulnerability Test
#
# McAfee ePolicy Orchestrator (ePO) Security Bypass Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803863");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-4594");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-08-09 12:24:03 +0530 (Fri, 09 Aug 2013)");
  script_name("McAfee ePolicy Orchestrator (ePO) Security Bypass Vulnerability");
  script_tag(name:"summary", value:"McAfee ePolicy Orchestrator is prone to a security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"According to vendor advisory, no remediation steps are required.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaw is due to an improper parsing of an ID value in a console URL.");
  script_tag(name:"affected", value:"McAfee ePolicy Orchestrator (ePO) version 4.6.1 and earlier");
  script_tag(name:"impact", value:"Successful exploitation will allow remote authenticated attacker to gain
access to potentially sensitive information.");

  script_xref(name:"URL", value:"http://cxsecurity.com/cveshow/CVE-2012-4594");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55183");
  script_xref(name:"URL", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10025");
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

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:vers, test_version:"4.6.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.6.1");
  security_message(port:port, data:report);
  exit(0);
}
