# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.807312");
  script_cve_id("CVE-2013-7446", "CVE-2015-7799", "CVE-2015-7833", "CVE-2015-8104");
  script_tag(name:"creation_date", value:"2016-03-08 07:08:02 +0000 (Tue, 08 Mar 2016)");
  script_version("2023-03-13T10:19:44+0000");
  script_tag(name:"last_modification", value:"2023-03-13 10:19:44 +0000 (Mon, 13 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)");

  script_name("Debian: Security Advisory (DSA-3426)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3426");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3426");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3426 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The update for linux issued as DSA-3426-1 and DSA-3434-1 to address CVE-2015-8543 uncovered a bug in ctdb, a clustered database to store temporary data, leading to broken clusters. Updated packages are now available to address this problem.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.12+git20120201-5.

For the stable distribution (jessie), this problem has been fixed in version 2.5.4+debian0-4+deb8u1.

We recommend that you upgrade your ctdb packages.

This VT has been deprecated as a duplicate of the VT 'Debian Security Advisory DSA 3426-1 (linux - security update)' (OID: 1.3.6.1.4.1.25623.1.0.703426).");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
