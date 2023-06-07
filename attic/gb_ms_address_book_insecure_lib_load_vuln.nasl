###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Address Book Insecure Library Loading Vulnerability
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801457");
  script_version("2021-10-05T12:25:15+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2021-10-05 12:25:15 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_cve_id("CVE-2010-3143");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Address Book Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/14778/");
  script_xref(name:"URL", value:"http://www.attackvector.org/new-dll-hijacking-exploits-many/");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to load arbitrary
  libraries by tricking a user into opening a vCard (.vcf).");

  script_tag(name:"affected", value:"- Microsoft Windows 7

  - Microsoft Windows XP SP3 and prior

  - Microsoft Windows Vista SP 2 and prior

  - Microsoft Windows Server 2008 SP 2 and prior

  - Microsoft Windows Server 2003 SP 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to the way Microsoft Address Book loads
  libraries in an insecure manner.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"Microsoft Address Book is prone to an insecure library loading vulnerability.

  This VT has been replaced by OID:1.3.6.1.4.1.25623.1.0.901169.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in secpod_ms10-096.nasl