# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0452");
  script_cve_id("CVE-2021-32785", "CVE-2021-32786", "CVE-2021-32791", "CVE-2021-32792");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-04 17:27:00 +0000 (Wed, 04 Aug 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0452)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0452");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0452.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29344");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/FZVF6BSJLRQZ7PFFR4X5JSU6KUJYNOCU/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-September/009431.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/54B4RYNP5L63X2FMX2QCVYB2LGLL42IY/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-mod_auth_openidc' package(s) announced via the MGASA-2021-0452 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In versions prior to 2.4.9, `oidc_validate_redirect_url()` does not parse
URLs the same way as most browsers do. As a result, this function can be
bypassed and leads to an Open Redirect vulnerability in the logout
functionality. (CVE-2021-32786)

In mod_auth_openidc before version 2.4.9, the AES GCM encryption in
mod_auth_openidc uses a static IV and AAD. It is important to fix because
this creates a static nonce and since aes-gcm is a stream cipher, this can
lead to known cryptographic issues, since the same key is being reused.
(CVE-2021-32791)

In mod_auth_openidc before version 2.4.9, there is an XSS vulnerability in
when using `OIDCPreservePost On`. (CVE-2021-32792)");

  script_tag(name:"affected", value:"'apache-mod_auth_openidc' package(s) on Mageia 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_auth_openidc", rpm:"apache-mod_auth_openidc~2.4.9.4~1.mga8", rls:"MAGEIA8"))) {
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
