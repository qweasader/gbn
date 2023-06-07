###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer 'CSS Import Rule' Use-after-free Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902325");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_cve_id("CVE-2010-3971");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer 'CSS Import Rule' Use-after-free Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code in the
  context of the application. Failed exploit attempts will result in
  denial-of-service conditions.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x.");

  script_tag(name:"insight", value:"The flaw is due to use-after-free error within the 'mshtml.dll' library
  when processing a web page referencing a 'CSS' file that includes various '@import' rules.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host has installed with Internet Explorer and is prone to
  a use after free vulnerability.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.901180.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3156");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45246");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/2488013.mspx");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-003.nasl
