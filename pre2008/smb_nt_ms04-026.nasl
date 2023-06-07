###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Tenable adds
# - check for OWA on port 80
# Updated: 2009/04/23 Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14254");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-0203");
  script_name("Vulnerability in Exchange Server 5.5 Outlook Web Access XSS (842436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"This vulnerability could allow an attacker to convince a user
  to run a malicious script. If this malicious script is run, it would execute
  in the security context of the user.
  Attempts to exploit this vulnerability require user interaction.

  This vulnerability could allow an attacker access to any data on the
  Outlook Web Access server that was accessible to the individual user.

  It may also be possible to exploit the vulnerability to manipulate Web browser caches
  and intermediate proxy server caches, and put spoofed content in those caches.");

  script_tag(name:"solution", value:"Apply the Windows Updates described in the references.");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2004/ms04-026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10902");

  script_tag(name:"summary", value:"The remote host is running a version of the Outlook Web Access which contains
  cross site scripting flaws.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("secpod_reg.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) ) exit( 0 );

cgi = "/exchange/root.asp";
if( ! http_is_cgi_installed_ka( item:cgi, port:port ) ) exit( 0 );

# now check for the patch
if( hotfix_check_nt_server() <= 0 ) exit( 0 );

vers = hotfix_check_exchange_installed();
if( isnull( vers ) ) exit( 0 );

if( hotfix_missing( name:"KB842436" ) > 0 )
  security_message( port:0 );
