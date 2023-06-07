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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0675.1");
  script_cve_id("CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-08-19T02:25:52+0000");
  script_tag(name:"last_modification", value:"2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 15:24:00 +0000 (Fri, 31 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0675-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0675-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150675-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'GnuTLS' package(s) announced via the SUSE-SU-2015:0675-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GnuTLS was updated to fix two security issues:

 * CVE-2015-0294: A certificate algorithm consistency checking issue
 was fixed, where GnuTLS did not check whether the two signature
 algorithms match on certificate import. This problem is not deemed
 to be exploitable currently.
 * CVE-2015-0282: GNUTLS-SA-2015-1: GnuTLS did not verify the RSA PKCS
 #1 signature algorithm to match the signature algorithm in the
 certificate, leading to a potential downgrade to a disallowed
 algorithm, such as MD5, without detecting it.

Security Issues:

 * CVE-2015-0294
 * CVE-2014-8155
 * CVE-2015-0282");

  script_tag(name:"affected", value:"'GnuTLS' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise High Availability Extension 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Software Development Kit 11-SP3, SUSE Manager 1.7.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~2.4.1~24.39.55.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-extra26", rpm:"libgnutls-extra26~2.4.1~24.39.55.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls26", rpm:"libgnutls26~2.4.1~24.39.55.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls26-32bit", rpm:"libgnutls26-32bit~2.4.1~24.39.55.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls26-x86", rpm:"libgnutls26-x86~2.4.1~24.39.55.1", rls:"SLES11.0SP3"))) {
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
