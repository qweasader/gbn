# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851748");
  script_version("2021-06-25T02:00:34+0000");
  script_tag(name:"last_modification", value:"2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-05-18 05:38:27 +0200 (Fri, 18 May 2018)");
  script_cve_id("CVE-2017-17688", "CVE-2017-17689");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for enigmail (openSUSE-SU-2018:1330-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'enigmail'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for enigmail to version 2.0.4 fixes multiple issues.

  Security issues fixed:

  - CVE-2017-17688: CFB gadget attacks allowed to exfiltrate plaintext out
  of encrypted emails. enigmail now fails on GnuPG integrity check
  warnings for old Algorithms (bsc#1093151)

  - CVE-2017-17689: CBC gadget attacks allows to exfiltrate plaintext out of
  encrypted emails (bsc#1093152)

  This update also includes new and updated functionality:

  - The Encryption and Signing buttons now work for both OpenPGP and S/MIME.
  Enigmail will chose between S/MIME or OpenPGP depending on whether the
  keys for all recipients are available for the respective standard

  - Support for the Autocrypt standard, which is now enabled by default

  - Support for Pretty Easy Privacy

  - Support for Web Key Directory (WKD)

  - The message subject can now be encrypted and replaced with a dummy
  subject, following the Memory Hole standard forprotected Email Headers

  - keys on keyring are automatically refreshed from keyservers at irregular
  intervals

  - Subsequent updates of Enigmail no longer require a restart of Thunderbird

  - Keys are internally addressed using the fingerprint instead of the key ID

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-470=1");

  script_tag(name:"affected", value:"enigmail on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:1330-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-05/msg00081.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"enigmail", rpm:"enigmail~2.0.4~12.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
