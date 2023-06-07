###############################################################################
# OpenVAS Vulnerability Test
#
# SSL/TLS: `includeSubDomains` Missing in HPKP Header
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108249");
  script_version("2021-01-26T13:20:44+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-01-26 13:20:44 +0000 (Tue, 26 Jan 2021)");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name('SSL/TLS: `includeSubDomains` Missing in HPKP Header');
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_hpkp_detect.nasl");
  script_mandatory_keys("hpkp/includeSubDomains/missing/port");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"The remote web server is missing the 'includeSubDomains' attribute in the HPKP header.

  Note: Most major browsers have dropped / deprecated support for this header in 2020.");

  script_tag(name:"solution", value:"Add the 'includeSubDomains' attribute to the HPKP header.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( ! port = get_kb_item( "hpkp/includeSubDomains/missing/port" ) )
  exit( 0 );

banner = get_kb_item( "hpkp/" + port + "/banner" );

log_message( port:port, data:'The remote web server is missing the "includeSubDomains" attribute in the HPKP header.\n\nHPKP Header:\n\n' + banner );
exit( 0 );
