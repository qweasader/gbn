# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842032");
  script_cve_id("CVE-2014-8564");
  script_tag(name:"creation_date", value:"2014-11-12 05:24:39 +0000 (Wed, 12 Nov 2014)");
  script_version("2023-06-21T05:06:21+0000");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:21 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2403-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.10");

  script_xref(name:"Advisory-ID", value:"USN-2403-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2403-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls28' package(s) announced via the USN-2403-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sean Burford discovered that GnuTLS incorrectly handled printing certain
elliptic curve parameters. A malicious remote server or client could use
this issue to cause GnuTLS to crash, resulting in a denial of service, or
possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'gnutls28' package(s) on Ubuntu 14.10.");

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

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"gnutls-bin", ver:"3.2.16-1ubuntu2.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-deb0-28", ver:"3.2.16-1ubuntu2.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutls-openssl27", ver:"3.2.16-1ubuntu2.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgnutlsxx28", ver:"3.2.16-1ubuntu2.1", rls:"UBUNTU14.10"))) {
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
