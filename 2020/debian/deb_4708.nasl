# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704708");
  script_cve_id("CVE-2020-14093", "CVE-2020-14954");
  script_tag(name:"creation_date", value:"2020-06-23 03:00:06 +0000 (Tue, 23 Jun 2020)");
  script_version("2023-06-20T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:21 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4708)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4708");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4708");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4708");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/neomutt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'neomutt' package(s) announced via the DSA-4708 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Damian Poddebniak and Fabian Ising discovered two security issues in the STARTTLS handling of the Neomutt mail client, which could enable MITM attacks.

For the stable distribution (buster), these problems have been fixed in version 20180716+dfsg.1-1+deb10u1.

We recommend that you upgrade your neomutt packages.

For the detailed security status of neomutt please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'neomutt' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"neomutt", ver:"20180716+dfsg.1-1+deb10u1", rls:"DEB10"))) {
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
