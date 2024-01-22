# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5554");
  script_cve_id("CVE-2023-39417", "CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870");
  script_tag(name:"creation_date", value:"2023-11-15 04:20:08 +0000 (Wed, 15 Nov 2023)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-13 22:15:00 +0000 (Wed, 13 Dec 2023)");

  script_name("Debian: Security Advisory (DSA-5554-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5554-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5554-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5554");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/postgresql-13");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-13' package(s) announced via the DSA-5554-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the PostgreSQL database system.

CVE-2023-5868

Jingzhou Fu discovered a memory disclosure flaw in aggregate function calls.

CVE-2023-5869

Pedro Gallegos reported integer overflow flaws resulting in buffer overflows in the array modification functions.

CVE-2023-5870

Hemanth Sandrana and Mahendrakar Srinivasarao reported that the pg_cancel_backend role can signal certain superuser processes, potentially resulting in denial of service.

CVE-2023-39417

Micah Gate, Valerie Woolard, Tim Carey-Smith, and Christoph Berg reported that an extension script using @substitutions@ within quoting may allow to perform an SQL injection for an attacker having database-level CREATE privileges.

For the oldstable distribution (bullseye), these problems have been fixed in version 13.13-0+deb11u1.

We recommend that you upgrade your postgresql-13 packages.

For the detailed security status of postgresql-13 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-13' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-compat3", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg-dev", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libecpg6", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpgtypes3", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq-dev", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpq5", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-13", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-client-13", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-doc-13", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plperl-13", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-plpython3-13", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-pltcl-13", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postgresql-server-dev-13", ver:"13.13-0+deb11u1", rls:"DEB11"))) {
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
