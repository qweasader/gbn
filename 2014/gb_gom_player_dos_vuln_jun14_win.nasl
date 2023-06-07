###############################################################################
# OpenVAS Vulnerability Test
#
# GOM Media Player Denial of Service Vulnerability Jun14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:gomlab:gom_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804638");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-3216");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-06-13 19:29:01 +0530 (Fri, 13 Jun 2014)");
  script_name("GOM Media Player Denial of Service Vulnerability Jun14 (Windows)");

  script_tag(name:"summary", value:"GOM Media Player is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an array indexing error within the 'gaf.ax' filter when
processing OGG files.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to corrupt memory and
cause a denial of service or execute an arbitrary code.");
  script_tag(name:"affected", value:"GOM Media Player version 2.2.57.5189 and before on Windows.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67385");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/33335");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126548");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_gom_player_detect_win.nasl");
  script_mandatory_keys("GOM/Player/Ver/Win");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!gomVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less_equal(version:gomVer, test_version:"2.2.57.5189"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
