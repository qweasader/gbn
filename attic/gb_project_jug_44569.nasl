# Copyright (C) 2010 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100888");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2010-11-02 13:46:58 +0100 (Tue, 02 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Project Jug Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44569");
  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Project.Jug.Directory.Traversal/54");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"This VT has been replaced by VT 'Generic HTTP Directory Traversal
  (HTTP Web Root Check)' (OID: 1.3.6.1.4.1.25623.1.0.106756) and 'Generic HTTP Directory Traversal
  (Web Application Check) (OID: 1.3.6.1.4.1.25623.1.0.113002).

  Project Jug is prone to a directory-traversal vulnerability because it fails to sufficiently
  sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploiting this issue will allow an attacker to read files
  outside the webroot directory. Information harvested may aid in launching further attacks.");

  script_tag(name:"affected", value:"Project Jug 1.0.0.0 is vulnerable. Other versions may also be
  affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);