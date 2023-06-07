###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Clickjacking Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800347");
  script_version("2020-06-16T11:20:34+0000");
  script_tag(name:"last_modification", value:"2020-06-16 11:20:34 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"creation_date", value:"2009-02-04 15:43:54 +0100 (Wed, 04 Feb 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0369");
  script_name("Microsoft Internet Explorer Clickjacking Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7912");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code and can retrieve sensitive information from the affected application.");

  script_tag(name:"affected", value:"Microsoft Windows Internet Explorer version 7.x.");

  script_tag(name:"insight", value:"Attackers will trick users into visiting an arbitrary URL via an onclick
  action that moves a crafted element to the current mouse position.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host has installed Internet Explorer and is prone to
  clickjacking vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

if( ! version = get_kb_item( "MS/IE/Version" ) )
  exit( 0 );

if( version =~ "^7\." ) {
  security_message( port:0 );
  exit( 0 );
}

exit( 99 );
