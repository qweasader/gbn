# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.480");
  script_cve_id("CVE-2015-7181", "CVE-2015-7182", "CVE-2016-1938", "CVE-2016-1950", "CVE-2016-1978", "CVE-2016-1979");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-18 18:01:56 +0000 (Fri, 18 Mar 2016)");

  script_name("Debian: Security Advisory (DLA-480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-480-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/DLA-480-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DLA-480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security update fixes serious security issues in NSS including arbitrary code execution and remote denial service attacks.

For Debian 7 wheezy, these problems have been fixed in 3.14.5-1+deb7u6. We recommend you upgrade your nss packages as soon as possible.

CVE-2015-7181

The sec_asn1d_parse_leaf function improperly restricts access to an unspecified data structure.

CVE-2015-7182

Heap-based buffer overflow in the ASN.1 decoder.

CVE-2016-1938

The s_mp_div function in lib/freebl/mpi/mpi.c in improperly divides numbers, which might make it easier for remote attackers to defeat cryptographic protection mechanisms.

CVE-2016-1950

Heap-based buffer overflow allows remote attackers to execute arbitrary code via crafted ASN.1 data in an X.509 certificate.

CVE-2016-1978

Use-after-free vulnerability in the ssl3_HandleECDHServerKeyExchange function allows remote attackers to cause a denial of service or possibly have unspecified other impact by making an SSL (1) DHE or (2) ECDHE handshake at a time of high memory consumption.

CVE-2016-1979

Use-after-free vulnerability in the PK11_ImportDERPrivateKeyInfoAndReturnKey function allows remote attackers to cause a denial of service or possibly have unspecified other impact via crafted key data with DER encoding.

Further information about Debian LTS security Advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libnss3", ver:"2:3.14.5-1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-1d", ver:"2:3.14.5-1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dbg", ver:"2:3.14.5-1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-dev", ver:"2:3.14.5-1+deb7u6", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnss3-tools", ver:"2:3.14.5-1+deb7u6", rls:"DEB7"))) {
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
