# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.53890");
  script_cve_id("CVE-2003-0459");
  script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
  script_version("2022-07-19T10:11:08+0000");
  script_tag(name:"last_modification", value:"2022-07-19 10:11:08 +0000 (Tue, 19 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Slackware: Security Advisory (SSA:2003-213-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SSA:2003-213-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.334526");
  script_xref(name:"URL", value:"https://kde.org/info/security/advisory-20030729-1.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'KDE' package(s) announced via the SSA:2003-213-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New KDE packages are available for Slackware 9.0.  These address a
security issue where Konqueror may leak authentication credentials.


Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
Fri Aug  1 15:15:51 PDT 2003
patches/packages/kde/*:  Upgraded to KDE 3.1.3.
  Note that this update addresses a security problem in Konqueror which may
  cause authentication credentials to be leaked to an unintended website
  through the HTTP-referer header when they have been entered into Konqueror
  as a URL of the form:
    http://user:password@example.com/
  For more information about this issue, please see the KDE advisory:
    [link moved to references]
We recommend that sites running KDE install this update.
(* Security fix *)
patches/packages/kdei/*:  New internationalization packages for KDE 3.1.3.
+--------------------------+");

  script_tag(name:"affected", value:"'KDE' package(s) on Slackware 9.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  # nb: Deprecated because of the broken FTP URL (containing * instead of a proper version) in the advisory
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
