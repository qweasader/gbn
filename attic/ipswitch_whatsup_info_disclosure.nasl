###############################################################################
# OpenVAS Vulnerability Test
#
# Ipswitch WhatsUp Professional Multiple Vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2008 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.80068");
  script_version("2022-12-08T10:12:32+0000");
  script_tag(name:"last_modification", value:"2022-12-08 10:12:32 +0000 (Thu, 08 Dec 2022)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2006-2351", "CVE-2006-2352", "CVE-2006-2353", "CVE-2006-2354", "CVE-2006-2355",
                "CVE-2006-2356", "CVE-2006-2357");
  script_xref(name:"OSVDB", value:"25469");
  script_xref(name:"OSVDB", value:"25470");
  script_xref(name:"OSVDB", value:"25471");
  script_xref(name:"OSVDB", value:"25472");
  script_name("Ipswitch WhatsUp Professional Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 David Maciejak");
  script_family("Web application abuses");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"summary", value:"Deprecated since it didn't check for any version or doing any
  active vulnerability evaluation.

  The remote web server is affected by multiple flaws.

  Description :

  The remote host appears to be running Ipswitch WhatsUp Professional, which is used to monitor states of
  applications, services and hosts.

  The version of WhatsUp Professional installed on the remote host is prone to multiple issues, including source
  code disclosure and cross-site scripting vulnerabilities.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/433808/30/0/threaded");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/17964");
  script_xref(name:"URL", value:"http://www.ipswitch.com/products/whatsup/professional/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"deprecated", value: TRUE);

  exit(0);
}

exit(66);
