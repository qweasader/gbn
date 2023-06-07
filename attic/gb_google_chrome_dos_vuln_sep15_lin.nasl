###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Denial of Service Vulnerability September15 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806055");
  script_version("2021-10-05T12:25:15+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 12:25:15 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"creation_date", value:"2015-09-21 12:57:12 +0530 (Mon, 21 Sep 2015)");
  script_name("Google Chrome Denial of Service Vulnerability (Sep 2015) - Linux");

  script_tag(name:"summary", value:"Google Chrome is prone to a denial of service (DoS) vulnerability.

  This VT has been replaced by the VT 'Google Chrome Multiple Vulnerabilities-01 Oct15 (Linux)' (OID: 1.3.6.1.4.1.25623.1.0.805996).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to browser address field
  does not properly sanitize user supplied input.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  attackers to crash the application.");

  script_tag(name:"affected", value:"Google Chrome version 45.0.2454.93 and prior.");

  script_tag(name:"solution", value:"Update to Google Chrome version
  46.0.2490.71 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.dnaindia.com/scitech/report-a-vulnerability-in-google-chrome-causes-it-to-crash-by-entering-a-simple-text-string-2127143");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);