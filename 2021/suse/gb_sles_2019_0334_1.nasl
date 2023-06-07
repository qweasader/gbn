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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.0334.1");
  script_cve_id("CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:30 +0000 (Wed, 09 Jun 2021)");
  script_version("2022-04-07T14:48:57+0000");
  script_tag(name:"last_modification", value:"2022-04-07 14:48:57 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-16 19:04:00 +0000 (Mon, 16 Dec 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:0334-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:0334-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20190334-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nginx' package(s) announced via the SUSE-SU-2019:0334-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nginx to version 1.14.2 fixes the following issues:

Security vulnerabilities addressed:
CVE-2018-16843 CVE-2018-16844: Fixed an issue whereby a client using
 HTTP/2 might cause excessive memory consumption and CPU usage
 (bsc#1115025 bsc#1115022).

CVE-2018-16845: Fixed an issue which might result in worker process
 memory disclosure whne processing of a specially crafted mp4 file with
 the ngx_http_mp4_module (bsc#1115015).

Other bug fixes and changes made:
Fixed an issue with handling of client addresses when using unix domain
 listen sockets to work with datagrams on Linux.

The logging level of the 'http request', 'https proxy request',
 'unsupported protocol', 'version too low', 'no suitable key share', and
 'no suitable signature algorithm' SSL errors has been lowered from
 'crit' to 'info'.

Fixed an issue with using OpenSSL 1.1.0 or newer it was not possible to
 switch off 'ssl_prefer_server_ciphers' in a virtual server if it was
 switched on in the default server.

Fixed an issue with TLS 1.3 always being enabled when built with OpenSSL
 1.1.0 and used with 1.1.1

Fixed an issue with sending a disk-buffered request body to a gRPC
 backend

Fixed an issue with connections of some gRPC backends might not be
 cached when using the 'keepalive' directive.

Fixed a segmentation fault, which might occur in a worker process if the
 ngx_http_mp4_module was used on 32-bit platforms.

Fixed an issue, whereby working with gRPC backends might result in
 excessive memory consumption.");

  script_tag(name:"affected", value:"'nginx' package(s) on SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Server Applications 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"nginx", rpm:"nginx~1.14.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debuginfo", rpm:"nginx-debuginfo~1.14.2~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nginx-debugsource", rpm:"nginx-debugsource~1.14.2~3.3.1", rls:"SLES15.0"))) {
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
