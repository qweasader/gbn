###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SMTP Service and Exchange Routing Engine Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:microsoft:exchange_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100607");
  script_version("2022-12-05T10:11:03+0000");
  script_cve_id("CVE-2004-0840");
  script_name("Microsoft SMTP Service and Exchange Routing Engine Buffer Overflow Vulnerability");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2010-04-26 19:54:51 +0200 (Mon, 26 Apr 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("SMTP problems");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("sw_ms_exchange_server_remote_detect.nasl");
  script_mandatory_keys("microsoft/exchange_server/smtp/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11374");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/870540");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-035");

  script_tag(name:"summary", value:"The Microsoft Windows 2003 SMTP Service and Exchange Routing Engine
  is prone to a buffer overflow. This occurs during the processing responses to DNS lookups.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow for remote code execution in the context of the
  vulnerable service.");

  script_tag(name:"solution", value:"Microsoft has released a bulletin that includes fixes to address this
  issue for supported versions of the operating system.

  Note that the fix for Exchange Server 2000 Service Pack 3 requires that the Exchange 2000 Server Post-Service Pack 3 (SP3)
  Update Rollup be installed as a prerequisite. See Knowledge Base article 870540 in the References section for further
  details on this rollup.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("version_func.inc");
include("host_details.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE, service:"smtp"))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

banner = smtp_get_banner(port:port);
if(!banner || "Microsoft ESMTP MAIL" >!< banner)
  exit(0);

version = eregmatch(pattern:"Version: ([0-9.]+)", string:banner);
if(!version[1])
  exit(0);

vers = split(version[1], sep:".", keep:FALSE);

if(int(vers[0]) == 6 && int(vers[1]) == 0 && int(vers[2]) > 2600) {
  if((int(vers[2]) == 3790 && int(vers[3]) < 211 ) || int(vers[2]) < 3790) {
    report = report_fixed_ver(installed_version:version[1], fixed_version:"See references");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
