# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877935");
  script_version("2020-06-09T07:30:09+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-06-09 07:30:09 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-07 03:28:06 +0000 (Sun, 07 Jun 2020)");
  script_name("Fedora: Security Advisory for perl-Email-MIME-ContentType (FEDORA-2020-22764f623f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"FEDORA", value:"2020-22764f623f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3PWODHVD5ZKQBY2OYBTFPBETUOOJA33D");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Email-MIME-ContentType'
  package(s) announced via the FEDORA-2020-22764f623f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This module is responsible for parsing email content type headers according
to section 5.1 of RFC 2045. It returns a hash with entries for the type, the
subtype, and a hash of attributes.

For backward compatibility with a really unfortunate misunderstanding of RFC
2045 by the early implementors of this module, &#39, discrete&#39, and &#39, composite&#39,
are
also present in the returned hashref, with the values of &#39, type&#39, and
&#39, subtype&#39,
respectively.");

  script_tag(name:"affected", value:"'perl-Email-MIME-ContentType' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Email-MIME-ContentType", rpm:"perl-Email-MIME-ContentType~1.024~1.fc32", rls:"FC32"))) {
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