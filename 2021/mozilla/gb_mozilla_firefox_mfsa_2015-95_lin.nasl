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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.2.1.2015.95");
  script_cve_id("CVE-2015-4498");
  script_tag(name:"creation_date", value:"2021-11-11 08:00:11 +0000 (Thu, 11 Nov 2021)");
  script_version("2021-11-15T09:54:42+0000");
  script_tag(name:"last_modification", value:"2021-11-15 09:54:42 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Mozilla Firefox Security Advisory (MFSA2015-95) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2015-95");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-95/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1042699");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Add-on notification bypass through data URLs
Security researcher Bas Venis reported a mechanism where add-ons could
be installed from a different source than user expectations. Normally, when a user enters
the URL to an add-on directly in the addressbar, warning prompts are bypassed because it
is the result of direct user action. He discovered that a data: URL could be
manipulated on a loaded page to simulate this direct user input of the add-on's URL, which
would result in a bypassing of the install permission prompt. He also reported that in the
absence of the permission prompt, it is possible to cause the actual installation prompt
to appear above another site's location by causing a page navigation immediately after
triggering add-on installation. This could manipulate a user into falsely believing a
trusted site (such as addons.mozilla.org) has
initiated the installation. This could lead to users installing an add-on from a malicious
source.");

  script_tag(name:"affected", value:"Firefox version(s) below 40.0.3.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "40.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "40.0.3", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
