###############################################################################
# OpenVAS Vulnerability Test
#
# phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103409");
  script_cve_id("CVE-2012-0834");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2012-02-02 12:25:56 +0100 (Thu, 02 Feb 2012)");
  script_name("phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51793");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/521450");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more details.");

  script_tag(name:"summary", value:"phpLDAPadmin is prone to a cross-site scripting vulnerability because
  it fails to properly sanitize user-supplied input.

  This VT has been replaced by the VT 'phpLDAPadmin 'base' Parameter Cross Site Scripting Vulnerability'
  (OID: 1.3.6.1.4.1.25623.1.0.802602).");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and launch other attacks.");

  script_tag(name:"affected", value:"phpLDAPadmin 1.2.2 is affected, other versions may also be vulnerable.");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

exit(66);
