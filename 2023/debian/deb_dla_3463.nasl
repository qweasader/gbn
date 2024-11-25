# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3463");
  script_cve_id("CVE-2019-6502", "CVE-2021-42779", "CVE-2021-42780", "CVE-2021-42781", "CVE-2021-42782", "CVE-2023-2977");
  script_tag(name:"creation_date", value:"2023-06-21 04:26:33 +0000 (Wed, 21 Jun 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-25 16:08:15 +0000 (Mon, 25 Apr 2022)");

  script_name("Debian: Security Advisory (DLA-3463-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3463-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3463-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/opensc");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'opensc' package(s) announced via the DLA-3463-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in opensc, a set of libraries and utilities to access smart cards, which could lead to application crash or information leak.

CVE-2019-6502

Dhiraj Mishra discovered a minor memory leak in the eidenv(1) CLI utility on an error-case.

CVE-2021-42779

A heap use after free vulnerability was discovered in sc_file_valid().

CVE-2021-42780

An use after return vulnerability was discovered in insert_pin(), which could potentially crash programs using the library.

CVE-2021-42781

Multiple heap buffer overflow vulnerabilities were discovered in pkcs15-oberthur.c, which could potentially crash programs using the library.

CVE-2021-42782

Multiple stack buffer overflow vulnerabilities were discovered in various places, which could potentially crash programs using the library.

CVE-2023-2977

A buffer overrun vulnerability was discovered in pkcs15 cardos_have_verifyrc_package(), which could lead to crash or information leak via smart card package with a malicious ASN1 context.

For Debian 10 buster, these problems have been fixed in version 0.19.0-1+deb10u2.

We recommend that you upgrade your opensc packages.

For the detailed security status of opensc please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'opensc' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"opensc", ver:"0.19.0-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"opensc-pkcs11", ver:"0.19.0-1+deb10u2", rls:"DEB10"))) {
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
