###############################################################################
# OpenVAS Vulnerability Test
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: David Fifield
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803506");
  script_version("2022-07-06T10:11:12+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-06 10:11:12 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2013-02-28 18:59:55 +0530 (Thu, 28 Feb 2013)");
  script_name("Nmap NSE 6.01: ssl-cert");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");

  script_tag(name:"summary", value:"Retrieves a server's SSL certificate.");

  script_tag(name:"insight", value:"The amount of information printed about the certificate depends
  on the verbosity level:

  - With no extra verbosity, the script prints the validity period and the commonName,
  organizationName, stateOrProvinceName, and countryName of the subject.

  - With '-v' it adds the issuer name and fingerprints.

  - With '-vv' it adds the PEM-encoded contents of the entire certificate.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);