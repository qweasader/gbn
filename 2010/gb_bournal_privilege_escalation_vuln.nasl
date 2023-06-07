##############################################################################
# OpenVAS Vulnerability Test
#
# Bournal Privilege Escalation Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800730");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2010-0118");
  script_name("Bournal Privilege Escalation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38554");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38353");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-6/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_bournal_detect.nasl");
  script_mandatory_keys("Bournal/Ver");

  script_tag(name:"insight", value:"The flaw exists while using temporary files in an insecure manner, which may
  allow attackers to overwrite arbitrary files via symlink attacks when running
  the update check via the '--hack_the_gibson' parameter.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Upgrade to Bournal 1.4.1");
  script_tag(name:"summary", value:"Bournal is prone to a privilege escalation vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform certain actions with
  escalated privileges.");
  script_tag(name:"affected", value:"Bournal version prior to 1.4.1");

  script_xref(name:"URL", value:"http://becauseinter.net/bournal/");
  exit(0);
}


include("version_func.inc");

bourVer = get_kb_item("Bournal/Ver");
if(!bourVer){
  exit(0);
}

if(version_is_less(version:bourVer, test_version:"1.4.1")){
   report = report_fixed_ver(installed_version:bourVer, fixed_version:"1.4.1");
   security_message(port: 0, data: report);
}
