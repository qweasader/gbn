# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.369.1");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-21T05:06:22+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:22 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-369-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU6\.06\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-369-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-369-1");
  script_xref(name:"URL", value:"http://www.postgresql.org/about/news.664");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql-8.1' package(s) announced via the USN-369-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Fuhr discovered an incorrect type check when handling unknown
literals. By attempting to coerce such a literal to the ANYARRAY type,
a local authenticated attacker could cause a server crash.

Josh Drake and Alvaro Herrera reported a crash when using aggregate
functions in UPDATE statements. A local authenticated attacker could
exploit this to crash the server backend. This update disables this
construct, since it is not very well defined and forbidden by the SQL
standard.

Sergey Koposov discovered a flaw in the duration logging. This could
cause a server crash under certain circumstances.

Please note that these flaws can usually not be exploited through web
and other applications that use a database and are exposed to
untrusted input, so these flaws do not pose a threat in usual setups.");

  script_tag(name:"affected", value:"'postgresql-8.1' package(s) on Ubuntu 6.06.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-8.1", ver:"8.1.4-0ubuntu1.1", rls:"UBUNTU6.06 LTS"))) {
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
