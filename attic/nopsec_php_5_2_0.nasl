# Copyright (C) 2012 NopSec Inc.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.110173");
  script_version("2022-03-16T16:30:47+0000");
  script_tag(name:"last_modification", value:"2022-03-16 16:30:47 +0000 (Wed, 16 Mar 2022)");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-1015", "CVE-2006-1549", "CVE-2006-2660", "CVE-2006-4486",
                "CVE-2006-4625", "CVE-2006-4812", "CVE-2006-5465", "CVE-2006-5706",
                "CVE-2006-7205", "CVE-2007-0448", "CVE-2007-1381", "CVE-2007-1584",
                "CVE-2007-1888", "CVE-2007-2844", "CVE-2007-5424");
  script_name("PHP < 5.2.0 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2012 NopSec Inc.");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);