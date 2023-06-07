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
  script_oid("1.3.6.1.4.1.25623.1.0.120100");
  script_cve_id("CVE-2014-9356", "CVE-2014-9357", "CVE-2014-9358");
  script_tag(name:"creation_date", value:"2015-09-08 11:17:24 +0000 (Tue, 08 Sep 2015)");
  script_version("2022-01-07T14:23:04+0000");
  script_tag(name:"last_modification", value:"2022-01-07 14:23:04 +0000 (Fri, 07 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Amazon Linux: Security Advisory (ALAS-2014-461)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Amazon Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");

  script_xref(name:"Advisory-ID", value:"ALAS-2014-461");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-461.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the ALAS-2014-461 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Path traversal attacks are possible in the processing of absolute symlinks. In checking symlinks for traversals, only relative links were considered. This allowed path traversals to exist where they should have otherwise been prevented. This was exploitable via both archive extraction and through volume mounts. This vulnerability allowed malicious images or builds from malicious Dockerfiles to write files to the host system and escape containerization, leading to privilege escalation. (CVE-2014-9356)

It has been discovered that the introduction of chroot for archive extraction in Docker 1.3.2 had introduced a privilege escalation vulnerability. Malicious images or builds from malicious Dockerfiles could escalate privileges and execute arbitrary code as a root user on the Docker host by providing a malicious 'xz' binary. (CVE-2014-9357)

It has been discovered that Docker does not sufficiently validate Image IDs as provided either via 'docker load' or through registry communications. This allows for path traversal attacks, causing graph corruption and manipulation by malicious images, as well as repository spoofing attacks. (CVE-2014-9358)");

  script_tag(name:"affected", value:"'docker' package(s) on Amazon Linux.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~1.3.3~1.0.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~1.3.3~1.0.amzn1", rls:"AMAZON"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-pkg-devel", rpm:"docker-pkg-devel~1.3.3~1.0.amzn1", rls:"AMAZON"))) {
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
