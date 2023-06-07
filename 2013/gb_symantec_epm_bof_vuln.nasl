###############################################################################
# OpenVAS Vulnerability Test
#
# Symantec Endpoint Protection Manager (SEPM) Buffer Overflow Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803882");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-1612");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-08-29 12:35:52 +0530 (Thu, 29 Aug 2013)");
  script_name("Symantec Endpoint Protection Manager (SEPM) Buffer Overflow Vulnerability");
  script_tag(name:"summary", value:"Symantec Endpoint Protection Manager is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to version 12.1.3 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"Flaw is due to a boundary error within secars.dll.");
  script_tag(name:"affected", value:"Symantec Endpoint Protection Manager (SEPM) version 12.1.x before 12.1.3");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause a buffer overflow via
the web based management console.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/60542");
  script_xref(name:"URL", value:"http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&suid=20130618_00");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Buffer overflow");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/Endpoint/Protection");
  script_exclude_keys("Symantec/SEP/SmallBusiness");
  exit(0);
}


include("version_func.inc");

sepVer = get_kb_item("Symantec/Endpoint/Protection");
if(!sepVer){
 exit(0);
}

if(sepVer && sepVer =~ "^12\.1")
{
  if(version_is_less(version:sepVer, test_version:"12.1.3"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
