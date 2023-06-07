# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2014.24");
  script_cve_id("CVE-2014-1506");
  script_tag(name:"creation_date", value:"2021-11-11 09:42:47 +0000 (Thu, 11 Nov 2021)");
  script_version("2022-09-22T10:44:54+0000");
  script_tag(name:"last_modification", value:"2022-09-22 10:44:54 +0000 (Thu, 22 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2014-24) - Deprecated");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");

  script_xref(name:"Advisory-ID", value:"MFSA2014-24");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-24/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=944374");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.

  This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Android Crash Reporter open to manipulation
Firefox for Android includes a Crash Reporter which sends crash data to
Mozilla for analysis. Security researcher Roee Hay reported
that third party Android applications could launch the crash reporter with their
own arguments. Normally applications cannot read the private files of another
application, but this vulnerability allowed a malicious application to specify a
local file in the Firefox profile and it to its own server leading to
information disclosure. The crash reporter can also be invoked in a manner
causing an immediate crash of Firefox, leading to a potential denial of service
(DOS) attack.");

  script_tag(name:"affected", value:"Firefox version(s) below 28.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
