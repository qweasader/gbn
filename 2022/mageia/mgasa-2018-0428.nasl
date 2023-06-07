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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0428");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-04-07T15:00:36+0000");
  script_tag(name:"last_modification", value:"2022-04-07 15:00:36 +0000 (Thu, 07 Apr 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mageia: Security Advisory (MGASA-2018-0428)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0428");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0428.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23127");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IQXVVVJM54QO6NGMMJJH56545OVCFQA4/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Cookie-Baker, perl-Dancer2, perl-HTTP-Entity-Parser, perl-HTTP-Headers-Fast, perl-HTTP-MultiPartParser, perl-HTTP-XSCookies, perl-JSON-MaybeXS, perl-Plack, perl-Type-Tiny, perl-WWW-Form-UrlEncoded' package(s) announced via the MGASA-2018-0428 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dancer2 0.206000 addresses several potential security issues. There is a
potential RCE with regards to Storable. Dancer2 adds session ID validation to
the session engine so that session backends based on Storable can reject
malformed session IDs that may lead to exploitation of the RCE. Parsing
requests now uses HTTP::Entity::Parser which reduces the amount of code needed
and does not require re-parsing the request body.

The perl-Dancer2 package has been updated to version 0.206.0 to fix this issue.

Also, the perl-HTTP-XSCookies, perl-WWW-Form-UrlEncoded,
perl-HTTP-MultiPartParser, and perl-HTTP-Entity-Parser dependencies have been
added and the perl-Type-Tiny, perl-HTTP-Headers-Fast, perl-JSON-MaybeXS,
perl-Cookie-Baker, and perl-Plack dependencies have been updated for the new
perl-Dancer2 version.");

  script_tag(name:"affected", value:"'perl-Cookie-Baker, perl-Dancer2, perl-HTTP-Entity-Parser, perl-HTTP-Headers-Fast, perl-HTTP-MultiPartParser, perl-HTTP-XSCookies, perl-JSON-MaybeXS, perl-Plack, perl-Type-Tiny, perl-WWW-Form-UrlEncoded' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"perl-Cookie-Baker", rpm:"perl-Cookie-Baker~0.100.0~1.2.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Dancer2", rpm:"perl-Dancer2~0.206.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-Entity-Parser", rpm:"perl-HTTP-Entity-Parser~0.210.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-Headers-Fast", rpm:"perl-HTTP-Headers-Fast~0.210.0~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-MultiPartParser", rpm:"perl-HTTP-MultiPartParser~0.20.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-HTTP-XSCookies", rpm:"perl-HTTP-XSCookies~0.0.21~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-JSON-MaybeXS", rpm:"perl-JSON-MaybeXS~1.4.0~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Plack", rpm:"perl-Plack~1.4.700~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Type-Tiny", rpm:"perl-Type-Tiny~1.4.2~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-WWW-Form-UrlEncoded", rpm:"perl-WWW-Form-UrlEncoded~0.250.0~1.mga6", rls:"MAGEIA6"))) {
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
