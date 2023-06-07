###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Security Bulletin MS07-040 - Critical
# Vulnerabilities in .NET Framework Could Allow Remote Code Execution
# NET PE Loader Vulnerability - CVE-2007-0041
# ASP.NET Null Byte Termination Vulnerability - CVE-2007-0042
# .NET JIT Compiler Vulnerability - CVE-2007-0043
#
# remote-MS07-040.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
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
  script_oid("1.3.6.1.4.1.25623.1.0.101005");
  script_version("2022-06-27T10:12:27+0000");
  script_tag(name:"last_modification", value:"2022-06-27 10:12:27 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2009-03-15 21:09:08 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0041", "CVE-2007-0042", "CVE-2007-0043");
  script_name("Microsoft Security Bulletin MS07-040");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "remote-detect-MSdotNET-version.nasl");
  script_mandatory_keys("dotNET/version");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-040");

  script_tag(name:"solution", value:"Microsoft has released an update to correct this issue,
  please see the reference for more information.");

  script_tag(name:"summary", value:"Microsoft .NET is affected by multiples criticals vulnerabilities.
  Two of these vulnerabilities could allow remote code execution on client systems with .NET Framework installed,
  and one could allow information disclosure on Web servers running ASP.NET.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");

dotnet = get_kb_item( "dotNET/version" );
if( ! dotnet ) exit( 0 );
port = get_kb_item( "dotNET/port" );

# Microsoft .NET Framework version < [1.0 SP3, 1.1 SP1, 2.0 SP2]
dotnetversion['1.0'] = revcomp( a:dotnet, b:"1.0.3705.6060" );
dotnetversion['1.1'] = revcomp( a:dotnet, b:"1.1.4332.2407" );
dotnetversion['2.0'] = revcomp( a:dotnet, b:"2.0.50727.832" );

foreach version( dotnetversion ) {
  if( version == -1 ) {
    # report MS07-04 vulnerability
    report = 'Missing MS07-040 patch, detected Microsoft .Net Framework version: ' + dotnet;
    security_message( port:port, data:report );
  }
}

exit( 99 );
