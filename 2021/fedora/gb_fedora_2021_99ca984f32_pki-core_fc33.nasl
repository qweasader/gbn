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
  script_oid("1.3.6.1.4.1.25623.1.0.879770");
  script_version("2022-03-02T03:04:15+0000");
  script_cve_id("CVE-2021-3551");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-02 03:04:15 +0000 (Wed, 02 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 15:51:00 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"creation_date", value:"2021-06-20 03:17:02 +0000 (Sun, 20 Jun 2021)");
  script_name("Fedora: Security Advisory for pki-core (FEDORA-2021-99ca984f32)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC33");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-99ca984f32");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZB5WOWM2LTAVOUH7UZMWRM6YL724TJRE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pki-core'
  package(s) announced via the FEDORA-2021-99ca984f32 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dogtag PKI is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

PKI consists of the following components:

  * Automatic Certificate Management Environment (ACME) Responder

  * Certificate Authority (CA)

  * Key Recovery Authority (KRA)

  * Online Certificate Status Protocol (OCSP) Manager

  * Token Key Service (TKS)

  * Token Processing Service (TPS)");

  script_tag(name:"affected", value:"'pki-core' package(s) on Fedora 33.");

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

if(release == "FC33") {

  if(!isnull(res = isrpmvuln(pkg:"pki-core", rpm:"pki-core~10.10.6~1.fc33", rls:"FC33"))) {
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