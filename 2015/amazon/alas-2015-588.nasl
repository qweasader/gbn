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
  script_oid("1.3.6.1.4.1.25623.1.0.120511");
  script_cve_id("CVE-2015-5739", "CVE-2015-5740", "CVE-2015-5741");
  script_tag(name:"creation_date", value:"2015-09-08 11:28:16 +0000 (Tue, 08 Sep 2015)");
  script_version("2023-11-02T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-11-02 05:05:26 +0000 (Thu, 02 Nov 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-14 15:57:00 +0000 (Fri, 14 Feb 2020)");

  script_name("Amazon Linux: Security Advisory (ALAS-2015-588)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2015-588");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2015-588.html");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q3/294");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2015/q3/237");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang, docker' package(s) announced via the ALAS-2015-588 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"As discussed upstream -- here and here -- the Go project received notification of an HTTP request smuggling vulnerability in the net/http library. Invalid headers are parsed as valid headers (like 'Content Length:' with a space in the middle) and Double Content-length headers in a request does not generate a 400 error, the second Content-length is ignored.");

  script_tag(name:"affected", value:"'golang, docker' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.6.2~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.6.2~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.6.2~1.3.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-bin-linux-386", rpm:"golang-pkg-bin-linux-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-bin-linux-amd64", rpm:"golang-pkg-bin-linux-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-darwin-386", rpm:"golang-pkg-darwin-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-darwin-amd64", rpm:"golang-pkg-darwin-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-freebsd-386", rpm:"golang-pkg-freebsd-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-freebsd-amd64", rpm:"golang-pkg-freebsd-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-freebsd-arm", rpm:"golang-pkg-freebsd-arm~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-linux-386", rpm:"golang-pkg-linux-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-linux-amd64", rpm:"golang-pkg-linux-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-linux-arm", rpm:"golang-pkg-linux-arm~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-netbsd-386", rpm:"golang-pkg-netbsd-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-netbsd-amd64", rpm:"golang-pkg-netbsd-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-netbsd-arm", rpm:"golang-pkg-netbsd-arm~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-openbsd-386", rpm:"golang-pkg-openbsd-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-openbsd-amd64", rpm:"golang-pkg-openbsd-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-plan9-386", rpm:"golang-pkg-plan9-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-plan9-amd64", rpm:"golang-pkg-plan9-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-windows-386", rpm:"golang-pkg-windows-386~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-pkg-windows-amd64", rpm:"golang-pkg-windows-amd64~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.4.2~3.16.amzn1", rls:"AMAZON"))) {
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
