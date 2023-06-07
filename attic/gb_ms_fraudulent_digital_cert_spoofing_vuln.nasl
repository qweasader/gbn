###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows Fraudulent Digital Certificates Spoofing Vulnerability (2641690)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802403");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-11-11 12:04:44 +0530 (Fri, 11 Nov 2011)");
  script_name("Microsoft Windows Fraudulent Digital Certificates Spoofing Vulnerability (2641690)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2641690");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/294871");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/SecurityAdvisories/2011/2641690");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to spoof content, perform
  phishing attacks or perform man-in-the-middle attacks against all Web browser
  users including users of Internet Explorer.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 Service Pack 1 and prior

  - Microsoft Windows XP Service Pack 3 and prior

  - Microsoft Windows Vista Service Pack 2 and prior

  - Microsoft Windows Server 2003 Service Pack 2 and prior

  - Microsoft Windows Server 2008 Service Pack 2 and prior");

  script_tag(name:"insight", value:"The flaw is due to an error when handling the fraudulent digital
  certificates issued by Entrust and GTE CyberTrust. It is not properly
  validating its identity.");

  script_tag(name:"solution", value:"Apply the Patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Microsoft Windows operating system is prone to a spoofing vulnerability.

  This VT has been superseded by KB2718704 Which is addressed in VT gb_unauth_digital_cert_spoofing_vuln.nasl (OID:1.3.6.1.4.1.25623.1.0.802634).");

  exit(0);
}

exit(66); # This VT is deprecated as it is superseded by KB2718704 Which is addressed in gb_unauth_digital_cert_spoofing_vuln.nasl