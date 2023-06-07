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
  script_oid("1.3.6.1.4.1.25623.1.0.120640");
  script_cve_id("CVE-2015-5244");
  script_tag(name:"creation_date", value:"2016-02-11 05:16:48 +0000 (Thu, 11 Feb 2016)");
  script_version("2021-10-12T09:01:32+0000");
  script_tag(name:"last_modification", value:"2021-10-12 09:01:32 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-16 16:16:00 +0000 (Wed, 16 Aug 2017)");

  script_name("Amazon Linux: Security Advisory (ALAS-2016-650)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2016-650");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2016-650.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mod24_nss' package(s) announced via the ALAS-2016-650 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the parsing of the NSSCipherSuite option of mod24_nss, which accepts OpenSSL-style cipherstrings, is flawed. If the option is used to disable insecure ciphersuites using the common '!' syntax, it will actually enable those insecure ciphersuites. (CVE-2015-5244)");

  script_tag(name:"affected", value:"'mod24_nss' package(s) on Amazon Linux.");

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

if(release == "AMAZON") {

  if(!isnull(res = isrpmvuln(pkg:"mod24_nss", rpm:"mod24_nss~1.0.12~1.21.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mod24_nss-debuginfo", rpm:"mod24_nss-debuginfo~1.0.12~1.21.amzn1", rls:"AMAZON"))) {
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
