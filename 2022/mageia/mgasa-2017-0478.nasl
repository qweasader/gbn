# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0478");
  script_cve_id("CVE-2016-9131", "CVE-2016-9147", "CVE-2016-9444", "CVE-2016-9778", "CVE-2017-3135", "CVE-2017-3136", "CVE-2017-3137", "CVE-2017-3138", "CVE-2017-3142", "CVE-2017-3143");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0478)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0478");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0478.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20107");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01439");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01440");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01441");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01442");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01453");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01465");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01466");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01471");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01503");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01504");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01447");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01455");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01484");
  script_xref(name:"URL", value:"https://kb.isc.org/article/AA-01508");
  script_xref(name:"URL", value:"https://ftp.isc.org/isc/bind9/9.10.5-P3/RELEASE-NOTES-bind-9.10.5-P3.html");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3172-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3201-1/");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/usn/usn-3259-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the MGASA-2017-0478 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Bind incorrectly handled certain malformed responses
to an ANY query. A remote attacker could possibly use this issue to cause
Bind to crash, resulting in a denial of service (CVE-2016-9131).

It was discovered that Bind incorrectly handled certain malformed responses
to an ANY query. A remote attacker could possibly use this issue to cause
Bind to crash, resulting in a denial of service (CVE-2016-9147).

It was discovered that Bind incorrectly handled certain malformed DS record
responses. A remote attacker could possibly use this issue to cause Bind to
crash, resulting in a denial of service (CVE-2016-9444).

An error in handling certain queries can cause an assertion failure when a
server is using the nxdomain-redirect feature to cover a zone for which it is
also providing authoritative service. A vulnerable server could be
intentionally stopped by an attacker if it was using a configuration that met
the criteria for the vulnerability and if the attacker could cause it to accept
a query that possessed the required attributes (CVE-2016-9778).

It was discovered that Bind incorrectly handled rewriting certain query
responses when using both DNS64 and RPZ. A remote attacker could possibly
use this issue to cause Bind to crash, resulting in a denial of service
(CVE-2017-3135).

Oleg Gorokhov discovered that in some situations, Bind did not properly
handle DNS64 queries. An attacker could use this to cause a denial
of service (CVE-2017-3136).

It was discovered that the resolver in Bind made incorrect
assumptions about ordering when processing responses containing
a CNAME or DNAME. An attacker could use this cause a denial of
service (CVE-2017-3137).

Mike Lalumiere discovered that in some situations, Bind did
not properly handle invalid operations requested via its control
channel. An attacker with access to the control channel could cause
a denial of service (CVE-2017-3138).

Clement Berthaux discovered that Bind did not correctly check TSIG
authentication for zone transfer requests. An attacker could use this
to improperly transfer entire zones (CVE-2017-3142).

Clement Berthaux discovered that Bind did not correctly check TSIG
authentication for zone update requests. An attacker could use this
to improperly perform zone updates (CVE-2017-3143).");

  script_tag(name:"affected", value:"'bind' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.10.5.P3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.10.5.P3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.10.5.P3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.10.5.P3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.10.5.P3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-bind", rpm:"python-bind~9.10.5.P3~1.mga5", rls:"MAGEIA5"))) {
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
