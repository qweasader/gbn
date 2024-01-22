# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70545");
  script_cve_id("CVE-2011-4625");
  script_tag(name:"creation_date", value:"2012-02-11 07:26:59 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-12T16:12:10+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:10 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-2330-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2330-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2330-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2330");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'simplesamlphp' package(s) announced via the DSA-2330-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Issues were found in the handling of XML encryption in simpleSAMLphp, an application for federated authentication. The following two issues have been addressed:

It may be possible to use an SP as an oracle to decrypt encrypted messages sent to that SP.

It may be possible to use the SP as a key oracle which can be used to forge messages from that SP by issuing 300000-2000000 queries to the SP.

The oldstable distribution (lenny) does not contain simplesamlphp.

For the stable distribution (squeeze), this problem has been fixed in version 1.6.3-2.

The testing distribution (wheezy) will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.8.2-1.

We recommend that you upgrade your simplesamlphp packages.");

  script_tag(name:"affected", value:"'simplesamlphp' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"simplesamlphp", ver:"1.6.3-2", rls:"DEB6"))) {
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
