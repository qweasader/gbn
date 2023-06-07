# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108560");
  script_version("2023-03-14T10:20:43+0000");
  script_tag(name:"last_modification", value:"2023-03-14 10:20:43 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"creation_date", value:"2019-03-16 08:57:17 +0100 (Sat, 16 Mar 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Report outdated / end-of-life Scan Engine / Environment (local)");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("global_settings.nasl");
  # Greenbone OS (GOS) installations have their own update notification in the admin shell. In
  # addition the check isn't valid for the Greenbone Cloud Services (GCS) at all.
  # nb: FEED_NAME (in global_settings.nasl) is used because this VT would run / be launched on the
  # GCS otherwise which is something we don't want to do. A different approach is (at least
  # currently) not possible because we don't know from NASL side if we're running on the GCS or on
  # a GOS running on the Enterprise TRIAL.
  # The only drawback of that approach is that a Greenbone Enterprise TRIAL with a TRIAL GSF key is
  # missed but this is currently acceptable due to the restricted time frame of the trial.
  script_exclude_keys("keys/is_gsf");

  script_tag(name:"summary", value:"This script checks and reports an outdated or end-of-life scan
  engine for the following environments:

  - Greenbone Source Edition (GSE)

  - Greenbone Enterprise TRIAL (formerly Greenbone Security Manager TRIAL / Greenbone Community
  Edition (GCE))

  used for this scan.

  NOTE: While this is not, in and of itself, a security vulnerability, a severity is reported to
  make you aware of a possible decreased scan coverage or missing detection of vulnerabilities on
  the target due to e.g.:

  - missing functionalities

  - missing bugfixes

  - incompatibilities within the feed");

  script_tag(name:"solution", value:"Update to the latest available stable release for your scan
  environment. Please check the references for more information. If you're using packages provided
  by your Linux distribution please contact the maintainer of the used distribution / repository and
  request updated packages.

  If you want to accept the risk of a possible decreased scan coverage or missing detection of
  vulnerabilities on the target you can set a global override for this script as described in the
  linked GSM manual.");

  script_xref(name:"URL", value:"https://www.greenbone.net/en/testnow/");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/greenbone-community-edition-22-4-stable-initial-release-2022-07-25/12638");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/greenbone-community-edition-21-04-end-of-life/13837");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-21-04-end-of-life-initial-release-2021-04-16/8942");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-20-08-end-of-life-initial-release-2020-08-12/6312");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-11-end-of-life-initial-release-2019-10-14/3674");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-10-end-of-life-initial-release-2019-04-05/208");
  script_xref(name:"URL", value:"https://forum.greenbone.net/t/gvm-9-end-of-life-initial-release-2017-03-07/211");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/reports.html#creating-an-override");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "keys/is_gsf" ) )
  exit( 0 );

include("version_func.inc");
include("misc_func.inc");

# nb: Different version scheme (with / without leading 0) is expected.
expected_gsm_trial_ver = "22.04.9";
# nb: OPENVAS_VERSION returns the version of the scanner since GVM-10
expected_scanner_ver1 = "22.4.1";
# nb: See comment below why this is commented out.
#expected_scanner_ver2 = "11.0.1";

if( gos_vers = get_local_gos_version() ) {
  if( version_is_less( version:gos_vers, test_version:expected_gsm_trial_ver ) ) {
    report  = "Installed GSM TRIAL / GCE version:  " + gos_vers + '\n';
    report += "Latest available GSM TRIAL version: " + expected_gsm_trial_ver + '\n';
    report += "Reference URL:                      https://www.greenbone.net/en/testnow/";
    security_message( port:0, data:report );
    exit( 0 );
  }
} else if( OPENVAS_VERSION && OPENVAS_VERSION =~ "^[0-9.]+" ) {
  if( version_is_less( version:OPENVAS_VERSION, test_version:expected_scanner_ver1 ) ) {
    report  = "Version of installed component:           " + OPENVAS_VERSION + ' (Installed component: openvas-libraries on OpenVAS <= 9, openvas-scanner on GVM >= 10)\n';
    report += "Latest available openvas-scanner version: " + expected_scanner_ver1 + '\n';
    report += "Reference URL(s) for the latest available version: https://forum.greenbone.net/t/greenbone-community-edition-22-4-stable-initial-release-2022-07-25/12638";
    security_message( port:0, data:report );
    exit( 0 );
  # nb: Currently commented out for easier re-use once there are two supported GVM releases again.
  } #else if( OPENVAS_VERSION =~ "^11\.0\.[0-9]+" && version_is_less( version:OPENVAS_VERSION, test_version:expected_scanner_ver2 ) ) {
    #report  = "Installed GVM Libraries (gvm-libs) version:        " + OPENVAS_VERSION + '\n';
    #report += "Latest available GVM Libraries (gvm-libs) version: " + expected_scanner_ver2 + '\n';
    #report += "Reference URL(s) for the latest available version: https://forum.greenbone.net/t/gvm-11-end-of-life-initial-release-2019-10-14/3674";
    #security_message( port:0, data:report );
    #exit( 0 );
  #}
}

exit( 99 );
