# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.120255");
  script_cve_id("CVE-2010-2642", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_tag(name:"creation_date", value:"2015-09-08 11:21:38 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-07T03:03:10+0000");
  script_tag(name:"last_modification", value:"2022-01-07 03:03:10 +0000 (Fri, 07 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2012-40)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2012-40");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2012-40.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 't1lib' package(s) announced via the ALAS-2012-40 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two heap-based buffer overflow flaws were found in the way t1lib processed Adobe Font Metrics (AFM) files. If a specially-crafted font file was opened by an application linked against t1lib, it could cause the application to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2010-2642, CVE-2011-0433)

An invalid pointer dereference flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2011-0764)

A use-after-free flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2011-1553)

An off-by-one flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash or, potentially, execute arbitrary code with the privileges of the user running the application. (CVE-2011-1554)

An out-of-bounds memory read flaw was found in t1lib. A specially-crafted font file could, when opened, cause an application linked against t1lib to crash. (CVE-2011-1552)");

  script_tag(name:"affected", value:"'t1lib' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"t1lib", rpm:"t1lib~5.1.2~6.5.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"t1lib-apps", rpm:"t1lib-apps~5.1.2~6.5.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"t1lib-debuginfo", rpm:"t1lib-debuginfo~5.1.2~6.5.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"t1lib-devel", rpm:"t1lib-devel~5.1.2~6.5.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"t1lib-static", rpm:"t1lib-static~5.1.2~6.5.amzn1", rls:"AMAZON"))) {
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
