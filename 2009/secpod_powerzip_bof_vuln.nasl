# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900491");
  script_version("2022-02-22T15:13:46+0000");
  script_tag(name:"last_modification", value:"2022-02-22 15:13:46 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2009-03-31 07:06:59 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1059");
  script_name("PowerZip Stack Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8180");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_powerzip_detect.nasl");
  script_mandatory_keys("PowerZip/Ver");
  script_tag(name:"affected", value:"PowerZip Version 7.20 or prior.");
  script_tag(name:"insight", value:"Flaw is due to improper sanitization check for the compressed archive
  'zip' file and may lead to stack based buffer overflow.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"PowerZip is prone to Stack Buffer Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes
  via specially  crafted archive 'zip' files.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("version_func.inc");

zipVer = get_kb_item("PowerZip/Ver");
if(zipVer != NULL)
{
  if(version_is_less_equal(version:zipVer, test_version:"7.20")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
