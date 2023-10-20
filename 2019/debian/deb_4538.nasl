# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704538");
  script_cve_id("CVE-2019-13377", "CVE-2019-16275");
  script_tag(name:"creation_date", value:"2019-09-30 02:00:10 +0000 (Mon, 30 Sep 2019)");
  script_version("2023-07-05T05:06:17+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:17 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 16:10:00 +0000 (Mon, 18 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-4538)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DSA-4538");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4538");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4538");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/wpa");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wpa' package(s) announced via the DSA-4538 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in the WPA protocol implementation found in wpa_supplication (station) and hostapd (access point).

CVE-2019-13377

A timing-based side-channel attack against WPA3's Dragonfly handshake when using Brainpool curves could be used by an attacker to retrieve the password.

CVE-2019-16275

Insufficient source address validation for some received Management frames in hostapd could lead to a denial of service for stations associated to an access point. An attacker in radio range of the access point could inject a specially constructed unauthenticated IEEE 802.11 frame to the access point to cause associated stations to be disconnected and require a reconnection to the network.

For the stable distribution (buster), these problems have been fixed in version 2:2.7+git20190128+0c1e29f-6+deb10u1.

We recommend that you upgrade your wpa packages.

For the detailed security status of wpa please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'wpa' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"hostapd", ver:"2:2.7+git20190128+0c1e29f-6+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpagui", ver:"2:2.7+git20190128+0c1e29f-6+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant", ver:"2:2.7+git20190128+0c1e29f-6+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"wpasupplicant-udeb", ver:"2:2.7+git20190128+0c1e29f-6+deb10u1", rls:"DEB10"))) {
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
