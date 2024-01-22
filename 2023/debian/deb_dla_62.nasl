# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.62");
  script_cve_id("CVE-2014-1568");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DLA-62-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-62-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/DLA-62-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DLA-62-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Antoine Delignat-Lavaud from Inria discovered an issue in the way NSS (the Mozilla Network Security Service library) was parsing ASN.1 data used in signatures, making it vulnerable to a signature forgery attack.

An attacker could craft ASN.1 data to forge RSA certificates with a valid certification chain to a trusted CA.

This update fixes this issue for the NSS libraries.

Note that iceweasel, which is also affected by CVE-2014-1568, however has reached end-of-life in Squeeze(-LTS) and thus has not been fixed.

For Debian 6 Squeeze, these issues have been fixed in nss version 3.12.8-1+squeeze9");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"3.12.8-1+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d-dbg", ver:"3.12.8-1+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dev", ver:"3.12.8-1+squeeze9", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-tools", ver:"3.12.8-1+squeeze9", rls:"DEB6"))) {
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
