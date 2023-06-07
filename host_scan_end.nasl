# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103739");
  script_version("2022-12-20T10:11:13+0000");
  script_tag(name:"last_modification", value:"2022-12-20 10:11:13 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"creation_date", value:"2013-06-17 10:52:11 +0100 (Mon, 17 Jun 2013)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Host Scan End");
  # nb: Needs to run at the end of the scan because of the required info only available in this phase...
  script_category(ACT_END);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");

  script_tag(name:"summary", value:"This routine is the last action of scanning a host.

  It stores information about the applied VT Feed and Version as well as the applied Scanner
  version. Finally the time of finishing the scan of this host is determined and stored.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

SCRIPT_DESC = "Host Scan End";

include("host_details.inc");
include("misc_func.inc");
include("plugin_feed_info.inc");

if(OPENVAS_VERSION)
  register_host_detail(name:"scanned_with_scanner", value:OPENVAS_VERSION, desc:SCRIPT_DESC);

if(PLUGIN_SET)
  register_host_detail(name:"scanned_with_feedversion", value:PLUGIN_SET, desc:SCRIPT_DESC);

if(PLUGIN_FEED)
  register_host_detail(name:"scanned_with_feedtype", value:PLUGIN_FEED, desc:SCRIPT_DESC);

if(gos_version = get_local_gos_version())
  register_host_detail(name:"scanned_with_gosversion", value:gos_version, desc:SCRIPT_DESC);

# This stop time is only used by other VTs. The scanner will determine the actual stop
# time that will then be reported to the scanner client.
set_kb_item(name:"/tmp/stop_time", value:unixtime());

exit(0);
